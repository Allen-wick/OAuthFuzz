#!/usr/bin/env python3
"""Post-hoc corpus replay protocol — the coverage measurement
procedure, verbatim:

  "Upon completion of each trial, the generated test corpora from all fuzzers
   are systematically replayed against a pristine, instrumented instance of
   the target service. The final reported coverage is the union of all
   branches triggered by the replayed corpus."

Corpus sources per tool:
  aflnet     : <out>/queue/*      (raw mutated HTTP request bytes)
  boofuzz    : <out>/corpus_raw/*.req (captured via Target.send -> log_send)
  oauthfuzz  : <out>/interesting_cases.jsonl (sequence + overrides replayed
               through the same OAuthSUT protocol engine)

Protocol per campaign dir: start a PRISTINE instrumented instance (fresh
container + fresh JaCoCo workdir / Go covdir), replay every corpus item,
final dump+report -> replay_coverage.json {branch_pct, instr_pct, n_cases}.

Usage (one campaign dir):
  python3 replay_corpus.py --campaign results/matrix/oauthfuzz_keycloak_s1
Aggregate all done campaigns into a table:
  python3 replay_corpus.py --aggregate results/matrix
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.abspath(os.path.dirname(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

from common import RESULTS, TARGETS, isolate_jacoco, say  # noqa: E402


def campaign_info(campaign_dir):
    """(tool, target, seed) from the directory name <tool>_<target>_s<seed>."""
    name = os.path.basename(campaign_dir.rstrip('/'))
    m = re.match(r'^(aflnet|boofuzz|oauthfuzz)_(.+)_s(\d+)$', name)
    if not m:
        return None
    return m.group(1), m.group(2), int(m.group(3))


def send_raw(host, port, data, timeout=0.05):
    """Relay-equivalent raw send: connect, send, signal EOF, peek, close.

    The server registers coverage when it processes the request bytes; fully
    draining responses is unnecessary. BooFuzz token requests advertise
    Content-Length: 512 with a shorter body, so the server HOLDS the socket
    waiting for body bytes that never come — a long drain timeout makes a
    300K corpus take days. We send, shutdown(WR) (EOF lets the server
    proceed with the partial request), peek once briefly, and close."""
    try:
        with socket.create_connection((host, port), timeout=5.0) as s:
            s.settimeout(timeout)
            s.sendall(data)
            try:
                s.shutdown(socket.SHUT_WR)  # EOF: let the server proceed
                s.recv(4096)                # brief peek; response content unused
            except (socket.timeout, OSError):
                pass
        return True
    except Exception:
        return False


def replay_raw_dir(corpus_dir, host, port, workers=16):
    """Replay raw corpus files against (host, port) with a thread pool.

    Serial replay of a 300K-file BooFuzz corpus at even 50ms/request takes
    4+ hours; 16 concurrent senders bound the wall clock to ~15 min while
    each request still lands on the same pristine instance."""
    from concurrent.futures import ThreadPoolExecutor

    items = []
    for root, _dirs, files in os.walk(corpus_dir):
        for fn in sorted(files):
            path = os.path.join(root, fn)
            if fn in ('fuzzer_stats',) or fn.startswith('.'):
                continue
            items.append(path)
    n = ok = 0

    def _one(path):
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except Exception:
            return False
        if not data:
            return False
        return send_raw(host, port, data)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(_one, items):
            n += 1
            ok += int(r)
    return n, ok


class SutReplayer:
    """Replays OAuthFuzz interesting cases through the protocol engine."""

    def __init__(self, cfg_path):
        from run_oauth_fuzzing import get_target_manager  # noqa: F401 (ref)
        from OAuthMapper.OAuthSUT import OAuthSUT
        with open(cfg_path) as f:
            cfg = json.load(f)
        from core.config import OAuthConfig
        oauth_cfg = cfg.get('oauth', {})
        self.oc = OAuthConfig(
            base_url=oauth_cfg.get('base_url', 'http://127.0.0.1:8080'),
            realm=oauth_cfg.get('realm', 'master'),
            client_id=oauth_cfg.get('client_id', 'fuzz-client'),
            client_secret=oauth_cfg.get('client_secret', 'fuzz-client-secret'),
            redirect_uri=oauth_cfg.get('redirect_uri', 'http://127.0.0.1:7777/callback'),
            username=oauth_cfg.get('user', 'testuser'),
            password=oauth_cfg.get('password', 'testpass'),
            scope=oauth_cfg.get('scope', 'openid profile email'),
            target_type=cfg.get('target_type', 'keycloak'),
        )
        self.sut = OAuthSUT(self.oc, target_type=cfg.get('target_type', 'keycloak'))

    def replay_case(self, case):
        try:
            self.sut.reset()
            self.sut.set_symbol_overrides(case.get('overrides') or {})
            for symbol in case.get('sequence', []):
                self.sut.step(symbol)
            return True
        except Exception:
            return False


def parse_jacoco_report(workdir):
    xml = os.path.join(workdir, 'reports', 'coverage.xml')
    if not os.path.exists(xml):
        return None, None
    with open(xml, encoding='utf-8', errors='ignore') as f:
        body = f.read()
    branch = instr = None
    instr_all = re.findall(r'<counter type="INSTRUCTION" missed="(\d+)" covered="(\d+)"', body)
    if instr_all:
        miss, cov = map(int, instr_all[-1])
        instr = 100.0 * cov / max(1, cov + miss)
    branch_all = re.findall(r'<counter type="BRANCH" missed="(\d+)" covered="(\d+)"', body)
    if branch_all:
        miss, cov = map(int, branch_all[-1])
        branch = 100.0 * cov / max(1, cov + miss)
    return branch, instr


def replay_campaign(campaign_dir, duration_note=None):
    campaign_dir = os.path.abspath(campaign_dir)
    info = campaign_info(campaign_dir)
    if not info:
        say(f'[replay] cannot parse campaign dir {campaign_dir}')
        return False
    tool, target, seed = info
    out_json = os.path.join(campaign_dir, 'replay_coverage.json')
    if os.path.exists(out_json):
        say(f'[replay] {campaign_dir} already done')
        return True

    sampler = TARGETS[target]['sampler']
    replay_dir = os.path.join(campaign_dir, 'replay_instance')
    os.makedirs(replay_dir, exist_ok=True)
    inst_name = f'{target}-replay-s{seed}'

    # ---- prepare pristine instance config ----
    from common import load_cfg
    http = 38080 if sampler == 'jacoco' else TARGETS[target]['http']
    ov = {}
    if sampler == 'jacoco':
        jd = os.path.join(replay_dir, 'jacoco')
        os.makedirs(jd, exist_ok=True)
        ov['jacoco.work_dir'] = jd
        ov['jacoco.agent_port'] = 27300 + (seed % 50)
        if target == 'keycloak':
            ov.update({'keycloak.container_name': inst_name,
                       'keycloak.host_http_port': http,
                       'oauth.base_url': f'http://127.0.0.1:{http}',
                       'keycloak.health_check_url': f'http://127.0.0.1:{http}/realms/master',
                       # keep the replay instance small while campaign lanes
                       # hold most of the host RAM
                       'keycloak.jvm_args': ['-Xmx1024m', '-Xms256m',
                                             '-XX:+UseG1GC']})
        elif target == 'cxf_oauth':
            ov.update({'cxf_oauth.container_name': inst_name,
                       'cxf_oauth.http_port': http,
                       # the local image IS the correct instrumented build;
                       # without this the manager runs a BuildKit rebuild +
                       # docker.io pre-pull per replay instance, which dies
                       # whenever the registry network is degraded
                       'cxf_oauth.reuse_image': True,
                       'oauth.base_url': f'http://127.0.0.1:{http}'})
    else:
        # Go replay instances must run the -cover build (counters flush at
        # graceful stop); stock images write nothing to GOCOVERDIR.
        if target == 'authelia':
            ov['authelia.image'] = 'authelia-cover:latest'
            ov['authelia.container_name'] = inst_name
            ov['authelia.coverage_dir'] = os.path.join(replay_dir, 'cov')
            ov['authelia.coverage_enabled'] = True
        elif target == 'ory_hydra':
            ov['ory_hydra.image'] = 'hydra-cover:v2'
            ov['ory_hydra.container_name'] = inst_name
            ov['ory_hydra.coverage_dir'] = os.path.join(replay_dir, 'cov')
    cfg = load_cfg(target, ov)
    cfg_path = os.path.join(replay_dir, 'config_used.json')
    with open(cfg_path, 'w') as f:
        json.dump(cfg, f, indent=2)

    # ---- start pristine instance ----
    from common import ensure_up
    subprocess.run(['docker', 'rm', '-f', inst_name], capture_output=True)
    if not ensure_up(target, cfg_path, http=http):
        return False

    # ---- replay corpus ----
    n_cases = n_ok = 0
    t0 = time.time()
    if tool in ('aflnet', 'boofuzz'):
        corpus = os.path.join(campaign_dir, 'queue' if tool == 'aflnet'
                              else 'corpus_raw')
        if not os.path.isdir(corpus):
            say(f'[replay] no corpus at {corpus}')
            return False
        n_cases, n_ok = replay_raw_dir(corpus, '127.0.0.1', http)
    else:  # oauthfuzz
        cases_path = os.path.join(campaign_dir, 'interesting_cases.jsonl')
        if not os.path.exists(cases_path):
            say(f'[replay] no cases at {cases_path}')
            return False
        rep = SutReplayer(cfg_path)
        with open(cases_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    case = json.loads(line)
                except Exception:
                    continue
                n_cases += 1
                n_ok += int(rep.replay_case(case))

    say(f'[replay:{os.path.basename(campaign_dir)}] {n_ok}/{n_cases} cases '
        f'replayed in {time.time()-t0:.0f}s')

    # ---- final coverage read ----
    result = {'tool': tool, 'target': target, 'seed': seed,
              'n_cases': n_cases, 'n_ok': n_ok,
              'replay_seconds': round(time.time() - t0, 1)}
    if sampler == 'jacoco':
        from core.coverage import JaCoCoManager
        jm = JaCoCoManager(work_dir=os.path.join(replay_dir, 'jacoco'))
        agent_port = ov.get('jacoco.agent_port', TARGETS[target].get('port', 6300))
        try:
            jm.dump_coverage(port=agent_port)
        except Exception as e:
            say(f'[replay] final dump failed: {e}')
        # report needs the classpath libs (same injection as the sampler;
        # EXCLUDE the jar backup copies — duplicate FQNs abort the report CLI)
        import glob as _glob
        jars = []
        wd = os.path.join(replay_dir, 'jacoco')
        if target == 'keycloak':
            for p in _glob.glob(os.path.join(wd, 'keycloak_lib', '**',
                                             'org.keycloak.keycloak-*.jar'),
                                recursive=True):
                b = os.path.basename(p)
                if any(ex in b for ex in ('sssd-federation', 'kerberos-federation',
                                          'themes', 'admin-ui', 'account-ui')):
                    continue
                jars.append(p)
        else:
            for p in _glob.glob(os.path.join(wd, 'cxf_lib', 'extracted', 'WEB-INF', 'classes')):
                jars.append(p)
            for p in _glob.glob(os.path.join(wd, 'cxf_lib', '**', '*.jar'), recursive=True):
                if 'extracted' in p and os.path.basename(p).startswith('cxf-rt-rs-security-'):
                    jars.append(p)
        # dedup, preserve order
        seen = set()
        jars = [p for p in jars if not (p in seen or seen.add(p))]
        if jars:
            jm.set_classpaths(jars)
        jm.generate_report()
        branch, instr = parse_jacoco_report(os.path.join(replay_dir, 'jacoco'))
        result['branch_pct'] = branch
        result['instr_pct'] = instr
        subprocess.run(['docker', 'rm', '-f', inst_name], capture_output=True)
    else:
        # Go: counters flush at graceful stop
        subprocess.run(['docker', 'stop', '-t', '60', inst_name],
                       capture_output=True, timeout=180)
        from common import read_covdata_total
        # coverage_dir set by the manager inside cfg; locate from config
        sec = target
        covdir = cfg.get(sec, {}).get('coverage_dir') or os.path.join(replay_dir, 'cov')
        result['covdata_pct'] = read_covdata_total(covdir)
        subprocess.run(['docker', 'rm', '-f', inst_name], capture_output=True)

    with open(out_json, 'w') as f:
        json.dump(result, f, indent=2)
    say(f'[replay:{os.path.basename(campaign_dir)}] -> {out_json}: {result}')
    return True


def aggregate(root_dir):
    """Walk campaign dirs with replay_coverage.json -> coverage_table.json."""
    table = {}
    for name in sorted(os.listdir(root_dir)):
        d = os.path.join(root_dir, name)
        rj = os.path.join(d, 'replay_coverage.json')
        if not os.path.isdir(d) or not os.path.exists(rj):
            continue
        info = campaign_info(d)
        if not info:
            continue
        tool, target, seed = info
        with open(rj) as f:
            r = json.load(f)
        key = f'{target}|{tool}'
        table.setdefault(key, {})[f's{seed}'] = {
            'branch_pct': r.get('branch_pct'),
            'instr_pct': r.get('instr_pct'),
            'covdata_pct': r.get('covdata_pct'),
            'n_cases': r.get('n_cases')}
    out = os.path.join(root_dir, 'coverage_table.json')
    with open(out, 'w') as f:
        json.dump(table, f, indent=2)
    say(f'aggregate -> {out}')
    print(json.dumps(table, indent=2))


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--campaign', default=None)
    ap.add_argument('--aggregate', default=None)
    args = ap.parse_args()
    if args.campaign:
        replay_campaign(args.campaign)
    elif args.aggregate:
        aggregate(args.aggregate)
    else:
        ap.error('need --campaign or --aggregate')
