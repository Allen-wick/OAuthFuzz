#!/usr/bin/env python3
"""Shared campaign infrastructure for the CS (Computers & Security) revision.

Adapted from OAuthLancer implements/scripts/run_rq1_matrix.py (v2, fixes
F1-F4) with these revision-specific changes:
  - Real multi-seed protocol: every campaign gets fuzzing.seed=<s>.
  - OAuthFuzz campaigns run the plain OAuthFuzzMinimalFuzzer (mode aflnet,
    adapter boofuzz) with the new ablation switches (fuzzing.disable_ep /
    disable_cve_patterns / disable_feedback) injected via config.
  - AFLNet lanes receive PER-TARGET raw seeds (the v1 bug where all lanes
    fuzzed with CXF-shaped seeds is fixed: SEEDS is mandatory now).
  - Port/container isolation per campaign so several instances of the same
    target (ablation lanes) can run concurrently.
  - interesting_cases.jsonl is dumped per campaign (post-hoc replay input).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time

HERE = os.path.abspath(os.path.dirname(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
RESULTS = os.path.join(HERE, 'results')

# ----------------------------------------------------------------------------
# Target registry. `http` is the host port the manager exposes; `sampler`
# selects the coverage measurement; aflnet_port is the one-shot relay port.
# Multi-instance keys (container/http/agent) are only needed for lanes that
# run concurrent instances of the SAME target (ablation phase).
# ----------------------------------------------------------------------------
TARGETS = {
    'cxf_oauth': dict(http=8081, sampler='jacoco', port=6310, aflnet_port=26000,
                      mgr='targets_manager.cxf_oauth_manager',
                      cfg=os.path.join(REPO, 'configs', 'oauth_cxf.json')),
    'keycloak': dict(http=8080, sampler='jacoco', port=6300, aflnet_port=26010,
                     mgr='targets_manager.keycloak_manager',
                     cfg=os.path.join(REPO, 'configs', 'oauth_keycloak.json')),
    'authelia': dict(http=9091, sampler='covdata', aflnet_port=26020,
                     mgr='targets_manager.authelia_manager',
                     cfg=os.path.join(REPO, 'configs', 'oauth_authelia.json')),
    'ory_hydra': dict(http=4444, sampler='covdata', aflnet_port=26030,
                      mgr='targets_manager.ory_hydra_manager',
                      cfg=os.path.join(REPO, 'configs', 'oauth_ory_hydra.json')),
    'casdoor': dict(http=8000, sampler='covdata', aflnet_port=26040,
                    mgr='targets_manager.casdoor_manager',
                    cfg=os.path.join(REPO, 'configs', 'oauth_casdoor.json')),
}

LOG = threading.Lock()


def say(msg):
    with LOG:
        print(f'[{time.strftime("%H:%M:%S")}] {msg}', flush=True)


def sh(cmd, log_path=None, timeout=None, env=None):
    if log_path:
        with open(log_path, 'a') as lf:
            return subprocess.run(cmd, cwd=REPO, stdout=lf, stderr=subprocess.STDOUT,
                                  timeout=timeout, env=env)
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                          timeout=timeout, env=env)


def http_up(url, timeout_s=300):
    """TCP-connect liveness probe (Authelia serves TLS, so HTTP GET misfires)."""
    import socket
    import urllib.parse
    u = urllib.parse.urlparse(url)
    host, port = u.hostname or '127.0.0.1', u.port or (443 if u.scheme == 'https' else 80)
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        try:
            with socket.create_connection((host, port), timeout=5):
                return True
        except Exception:
            time.sleep(5)
    return False


def read_covdata_total(covdir):
    inner = os.path.join(covdir, 'coverage')
    if os.path.isdir(inner) and any(f.startswith('covmeta') for f in os.listdir(inner)):
        covdir = inner
    r = subprocess.run(['go', 'tool', 'covdata', 'func', '-i=' + covdir],
                       capture_output=True, text=True, timeout=300)
    for line in r.stdout.splitlines():
        if re.match(r'\s*total\s+\(statements\)', line):
            m = re.search(r'([\d.]+)%\s*$', line.strip())
            if m:
                return float(m.group(1))
    return None


def load_cfg(target, overrides=None):
    """Deep-copy the base config and apply dot-path overrides."""
    with open(TARGETS[target]['cfg']) as f:
        cfg = json.loads(json.dumps(json.load(f)))
    for key, val in (overrides or {}).items():
        node = cfg
        parts = key.split('.')
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = val
    return cfg


def prune_campaign_dir(out_dir, target):
    """Post-DONE slimming: drop bulky instrumentation artifacts (Java jacoco
    workdir with classpath libs + exec; Go snapshot copies), keeping the
    evidence files (config, logs, summary, interesting cases, coverage
    series/final). Replay uses its own pristine instance, so these are not
    needed after the campaign completes."""
    import shutil
    jd = os.path.join(out_dir, 'jacoco')
    if os.path.isdir(jd):
        shutil.rmtree(jd, ignore_errors=True)
    cov = os.path.join(out_dir, 'cov')
    if os.path.isdir(cov):
        # coverage_final.json already holds the measured covdata_pct; the
        # raw Go counters are GB-scale under high request rates (boofuzz
        # lanes grew cov/ to ~3GB within 2h) and the replay protocol uses
        # its own pristine instance — drop them entirely after DONE.
        if os.path.exists(os.path.join(out_dir, 'coverage_final.json')):
            shutil.rmtree(cov, ignore_errors=True)
        else:
            for d in os.listdir(cov):
                if d.startswith('snapshot_'):
                    shutil.rmtree(os.path.join(cov, d), ignore_errors=True)
    say(f'[prune] {os.path.basename(out_dir)} slimmed')


def ensure_up(target, cfg_path, mgr=None, http=None):
    """(Re)start the target via its manager CLI; wait for TCP."""
    mgr = mgr or TARGETS[target]['mgr']
    http = http or TARGETS[target]['http']
    sh([sys.executable, '-m', mgr, '--config', cfg_path, '--action', 'start'],
       log_path=os.path.join(RESULTS, 'manager.log'), timeout=1200)
    scheme = 'https' if target == 'authelia' else 'http'
    ok = http_up(f'{scheme}://127.0.0.1:{http}')
    if not ok:
        say(f'[ensure_up:{target}] FAILED (port {http})')
    return ok


def isolate_jacoco(target, out_dir):
    """F1-style isolation: per-campaign JaCoCo workdir with copied classpath
    libs so report generation works when the container is merely reused."""
    jd = os.path.join(out_dir, 'jacoco')
    os.makedirs(jd, exist_ok=True)
    lib_name = 'keycloak_lib' if target == 'keycloak' else 'cxf_lib'
    shared = os.path.join(REPO, 'jacoco_tools', lib_name)
    dst = os.path.join(jd, lib_name)
    if os.path.isdir(shared) and not os.path.exists(dst):
        shutil.copytree(shared, dst)
    return jd


# ----------------------------------------------------------------------------
# OAuthFuzz campaign (the tool under test)
# ----------------------------------------------------------------------------
ARMS = {
    # arm name -> fuzzing.* switch overrides
    'full':      {},
    'no_ep':     {'disable_ep': True},          # +DG only
    'no_fb':     {'disable_feedback': True},    # +EP only
    'baseline':  {'disable_ep': True, 'disable_feedback': True},
    'no_cve':    {'disable_cve_patterns': True} # Full minus CVE knowledge
}


def oauthfuzz_campaign(target, out_dir, seed, duration_h=6.0, arm='full',
                       inst=None, dry_smoke=False):
    """Run one OAuthFuzz campaign. `inst` = instance overrides for concurrent
    same-target lanes: {'container': name, 'http_port': p, 'agent_port': q}.
    Returns True when the campaign produced evidence (summary + alerts)."""
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    ov = {
        'output_dir': out_dir,
        'fuzzing.seed': seed,
        'fuzzing.save_interesting_cases': True,
        'fuzzing.budget_protocol_steps': 0,
        'fuzzing.dump_every_n': 200,
    }
    ov.update({f'fuzzing.{k}': v for k, v in ARMS[arm].items()})
    scheme = 'https' if target == 'authelia' else 'http'

    if TARGETS[target]['sampler'] == 'jacoco':
        jd = isolate_jacoco(target, out_dir)
        ov['jacoco.work_dir'] = jd
        # always pin a lane-distinct agent port (TARGETS registry default or
        # instance override) — concurrent lanes must not collide on 6300
        agent_port = (inst or {}).get('agent_port') or TARGETS[target].get('port')
        if agent_port:
            ov['jacoco.agent_port'] = agent_port
        if target == 'keycloak' and inst:
            ov['keycloak.container_name'] = inst['container']
            ov['keycloak.host_http_port'] = inst['http_port']
            ov['oauth.base_url'] = f'http://127.0.0.1:{inst["http_port"]}'
            ov['keycloak.health_check_url'] = f'http://127.0.0.1:{inst["http_port"]}/realms/master'
            if inst.get('jvm_args'):
                ov['keycloak.jvm_args'] = inst['jvm_args']
        if target == 'cxf_oauth' and inst:
            ov['cxf_oauth.container_name'] = inst['container']
            ov['oauth.base_url'] = f'http://127.0.0.1:{inst["http_port"]}'
    else:
        covdir = os.path.join(out_dir, 'cov')
        os.makedirs(covdir, exist_ok=True)
        sec = target if target != 'cxf_oauth' else 'cxf_oauth'
        ov[f'{sec}.coverage_dir'] = covdir
        ov[f'{sec}.coverage_enabled'] = True
        # Go targets MUST run the -cover build (stock image writes no
        # counters even with GOCOVERDIR set) — per OAuthLancer rq1 precedent
        if target == 'authelia':
            ov['authelia.image'] = 'authelia-cover:latest'
        elif target == 'ory_hydra':
            # hydra-cover:v2 lacks the sqlite driver (DSN=memory fails:
            # "sqlite3 support was not compiled into the binary"), so the
            # extra lane runs the Postgres recipe as an externally-managed
            # instance; coverage accumulates in a shared dir (discovery-only
            # lane — union over seeds, no per-seed statistics)
            ov.update({'ory_hydra.external_managed': True,
                       'ory_hydra.provision_script':
                           os.path.join(HERE, 'provision_extra_hydra.sh'),
                       # the health monitor inspects this container for
                       # liveness; a stale default name (ory-hydra-fuzz)
                       # reads as "exited" and trips a false CRASH stop
                       'ory_hydra.container_name': 'hydra-extra',
                       'ory_hydra.coverage_dir':
                           os.path.join(RESULTS, 'extra', 'hydra_extra_cov')})
        if inst:
            ov[f'{sec}.container_name'] = inst['container']
            ov['oauth.base_url'] = f'{scheme}://127.0.0.1:{inst["http_port"]}'

    cfg = load_cfg(target, ov)
    cfg_path = os.path.join(out_dir, 'config_used.json')
    with open(cfg_path, 'w') as f:
        json.dump(cfg, f, indent=2)

    http = inst['http_port'] if inst else TARGETS[target]['http']
    if not ensure_up(target, cfg_path, http=http):
        return False

    cmd = [sys.executable, os.path.join(REPO, 'run_oauth_fuzzing.py'),
           '--config', cfg_path, '--mode', 'aflnet', '--adapter', 'boofuzz',
           '--iterations', str(10 ** 9)]
    say(f'[oauthfuzz:{os.path.basename(out_dir)}] start arm={arm} seed={seed} ({duration_h}h)')
    t0 = time.time()
    with open(os.path.join(out_dir, 'start_epoch.json'), 'w') as f:
        json.dump({'start_epoch': t0}, f)
    env = dict(os.environ)
    # mid-run Go coverage snapshots are GB-scale with -cover builds; final
    # counters land in the GOCOVERDIR mount at graceful stop (read there)
    env['OAUTH_FUZZ_GO_SNAPSHOT'] = '0'
    proc = subprocess.Popen(cmd, cwd=REPO, env=env,
                            stdout=open(os.path.join(out_dir, 'run.log'), 'w'),
                            stderr=subprocess.STDOUT)
    deadline = t0 + (duration_h if not dry_smoke else dry_smoke) * 3600
    while proc.poll() is None and time.time() < deadline:
        time.sleep(30)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(300)
        except subprocess.TimeoutExpired:
            proc.kill()
    rc = proc.poll()
    say(f'[oauthfuzz:{os.path.basename(out_dir)}] end rc={rc} '
        f'in {(time.time()-t0)/3600:.2f}h')

    if TARGETS[target]['sampler'] == 'covdata':
        # manager already stopped the container in run_oauth_fuzzing finally;
        # covdata flushed by the manager's stop hook — read from the covdir
        covdir = os.path.join(out_dir, 'cov')
        pct = read_covdata_total(covdir)
        with open(os.path.join(out_dir, 'coverage_final.json'), 'w') as f:
            json.dump({'covdata_pct': pct}, f)
        say(f'[oauthfuzz:{os.path.basename(out_dir)}] final covdata = {pct}%')

    ok = os.path.exists(os.path.join(out_dir, 'fuzzing_summary.json'))
    return ok


# ----------------------------------------------------------------------------
# Baseline campaigns
# ----------------------------------------------------------------------------
def start_go_cover_container(target, out_dir, name, http):
    """Dedicated -cover container with its own GOCOVERDIR (Go baselines +
    authelia lanes). Uses the images built by build_*_cover.sh."""
    image = {'authelia': 'authelia-cover:latest',
             'ory_hydra': 'hydra-cover:v2'}.get(target)
    if image is None:
        say(f'[go-container:{target}] no cover image known')
        return False
    subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    covdir = os.path.join(out_dir, 'cov')
    datadir = covdir.rstrip('/') + '_data'
    os.makedirs(covdir, exist_ok=True)
    os.makedirs(datadir, exist_ok=True)
    if target == 'authelia':
        with open(TARGETS[target]['cfg']) as f:
            c = json.load(f)
        # config_dir in the base config is REPO-relative ("./targets_manager/...")
        # — docker resolves a relative bind source against OUR cwd, silently
        # creating an empty dir when launched from elsewhere (the Sept-21 bug
        # that invalidated five aflnet_authelia campaigns). Absolutize it.
        cfg_dir = c.get('authelia', {}).get(
            'config_dir', 'targets_manager/authelia_service/config')
        cfg_dir = os.path.abspath(os.path.join(REPO, cfg_dir))
        cmd = ['docker', 'run', '-d', '--name', name,
               '-p', f'{http}:9091',
               '-v', f'{cfg_dir}:/config:ro',
               '-v', f'{covdir}:/cov', '-v', f'{datadir}:/data',
               '-e', 'GOCOVERDIR=/cov', '-e', 'TZ=UTC',
               '-e', 'X_AUTHELIA_CONFIG_FILTERS=template',
               image, 'authelia', '--config', '/config/configuration.yml']
    else:  # ory_hydra
        cmd = ['docker', 'run', '-d', '--name', name,
               '-p', f'{http}:4444', '-p', f'{http + 1}:4445',
               '-v', f'{covdir}:/cov',
               '-e', 'GOCOVERDIR=/cov',
               image, 'serve', 'all', '--dev']
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        say(f'[go-container:{target}] failed: {r.stderr[-200:]}')
        return False
    return http_up(f'http://127.0.0.1:{http}')


def stop_container(name):
    subprocess.run(['docker', 'stop', '-t', '60', name], capture_output=True, timeout=180)
    subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


def baseline_campaign(kind, target, out_dir, duration_h=6.0, inst=None):
    """BooFuzz / AFLNet baseline. Java: live at-target sampling (sampler).
    Go: dedicated cover container, single flushed endpoint read."""
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    http = inst['http_port'] if inst else TARGETS[target]['http']
    sampler = None
    if TARGETS[target]['sampler'] == 'jacoco':
        if not ensure_up(target, os.path.join(out_dir, 'target_config.json')
                         if os.path.exists(os.path.join(out_dir, 'target_config.json'))
                         else _write_target_cfg(target, out_dir, inst), http=http):
            return False
        isolate_jacoco(target, out_dir)
        agent_port = inst['agent_port'] if inst else TARGETS[target]['port']
        sampler = subprocess.Popen(
            [sys.executable, os.path.join(HERE, 'coverage_sampler.py'),
             '--mode', 'jacoco', '--duration-h', str(duration_h),
             '--port', str(agent_port),
             '--jacoco-workdir', os.path.join(out_dir, 'jacoco'),
             '--out', os.path.join(out_dir, 'coverage_series.jsonl')],
            cwd=REPO, stdout=open(os.path.join(out_dir, 'sampler.log'), 'a'),
            stderr=subprocess.STDOUT)
    else:
        name = f'{target}-rev-base-{http}'
        if not start_go_cover_container(target, out_dir, name, http):
            return False

    aflnet_port = inst['aflnet_port'] if inst else TARGETS[target]['aflnet_port']
    say(f'[{kind}:{target}:{os.path.basename(out_dir)}] start ({duration_h}h)')
    if kind == 'boofuzz':
        sh([sys.executable, os.path.join(HERE, 'boofuzz_campaign.py'),
            '--target', target, '--duration-h', str(duration_h),
            '--port', str(http), '--out', out_dir],
           log_path=os.path.join(out_dir, 'sh.log'))
    else:
        env = dict(os.environ)
        env.update({'TARGET': target, 'UP_PORT': str(http),
                    'PORT': str(aflnet_port),
                    'DURATION_H': str(duration_h), 'OUT': out_dir,
                    'SEEDS': os.path.join(HERE, 'aflnet', f'seeds_{target}')})
        subprocess.run(['bash', os.path.join(HERE, 'aflnet', 'aflnet_campaign.sh')],
                       cwd=REPO, env=env,
                       stdout=open(os.path.join(out_dir, 'sh.log'), 'a'),
                       stderr=subprocess.STDOUT)
        subprocess.run(['bash', '-c',
                        'kill $(pgrep -f "relay_onesho[t]") 2>/dev/null; '
                        'kill $(pgrep -f "afl-fu[z]z") 2>/dev/null; true'])

    if sampler:
        sampler.terminate()
    if TARGETS[target]['sampler'] != 'jacoco':
        stop_container(f'{target}-rev-base-{http}')
        pct = read_covdata_total(os.path.join(out_dir, 'cov'))
        with open(os.path.join(out_dir, 'coverage_final.json'), 'w') as f:
            json.dump({'covdata_pct': pct}, f)
        say(f'[{kind}:{target}] final covdata = {pct}%')

    if kind == 'boofuzz':
        ok = os.path.isdir(os.path.join(out_dir, 'corpus_raw')) and \
            len(os.listdir(os.path.join(out_dir, 'corpus_raw'))) > 0
    else:
        # this AFLNet build never writes fuzzer_stats in dumb mode; the
        # honest liveness evidence is the pass cycle in campaign.log
        # (each pass runs ~2.25h; a 6h campaign completes 2-3 passes)
        clog = os.path.join(out_dir, 'campaign.log')
        passes = 0
        if os.path.exists(clog):
            with open(clog) as f:
                passes = sum(1 for line in f if 'pass ' in line and ' end ' in line)
        ok = passes >= 2
    say(f'[{kind}:{target}] end ok={ok}')
    return ok


def _write_target_cfg(target, out_dir, inst):
    """Isolated target config for baseline lanes (container/ports)."""
    path = os.path.join(out_dir, 'target_config.json')
    ov = {}
    if TARGETS[target]['sampler'] == 'jacoco':
        # Isolated JaCoCo workdir per campaign (F1) — the base config's
        # default work_dir is the SHARED jacoco_tools tree; running the
        # manager against it cross-contaminates coverage between lanes and
        # races concurrent lib copies.
        jd = isolate_jacoco(target, out_dir)
        ov['jacoco.work_dir'] = jd
        agent_port = (inst or {}).get('agent_port') or TARGETS[target].get('port')
        if agent_port:
            ov['jacoco.agent_port'] = agent_port
    if inst:
        if target == 'keycloak':
            ov.update({'keycloak.container_name': inst['container'],
                       'keycloak.host_http_port': inst['http_port'],
                       'keycloak.health_check_url': f'http://127.0.0.1:{inst["http_port"]}/realms/master',
                       'oauth.base_url': f'http://127.0.0.1:{inst["http_port"]}'})
            if inst.get('jvm_args'):
                # boofuzz lanes hammer keycloak at ~2k req/s; the default heap
                # died (exit 3) 2h into the first campaign under memory pressure
                ov['keycloak.jvm_args'] = inst['jvm_args']
        elif target == 'cxf_oauth':
            ov.update({'cxf_oauth.container_name': inst['container'],
                       'cxf_oauth.reuse_image': True,  # never rebuild per campaign
                       'oauth.base_url': f'http://127.0.0.1:{inst["http_port"]}'})
    cfg = load_cfg(target, ov)
    with open(path, 'w') as f:
        json.dump(cfg, f, indent=2)
    return path
