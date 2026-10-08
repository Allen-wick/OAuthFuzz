#!/usr/bin/env python3
"""Resurrection-aware replay for the boofuzz_keycloak corpora (Table 4's
last cells).

These corpora contain the deterministic ~2h kill-shot input (verified twice:
the container dies ~2h into live fuzzing, exit 3, auto-removed). A plain
replay would die mid-corpus and lose everything after the kill-shot.

Protocol per campaign:
  - pristine keycloak replay instance (kc-ks-replay :38082, agent 27302)
  - replay corpus files sequentially with the threaded raw sender semantics
    (serial here — the kill-shot ordering matters for reproducibility)
  - PERIODIC JaCoCo dump-with-reset every N files: the exec file accumulates
    the union; when the kill-shot kills the instance, coverage up to the
    last dump survives
  - on instance death: recreate via the manager (same config) and continue
    from the next file
  - final report from the accumulated exec

Usage: nohup python3 replay_kc_killshot.py > results/replay_kc_ks.log 2>&1 &
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', '..')))

from common import RESULTS, ensure_up, load_cfg, say  # noqa: E402
from replay_corpus import parse_jacoco_report, send_raw  # noqa: E402

INST = 'kc-ks-replay'
HTTP = 38082
AGENT = 27302
DUMP_EVERY = 2000


def build_cfg_path(campaign_dir):
    replay_dir = os.path.join(campaign_dir, 'replay_instance')
    os.makedirs(replay_dir, exist_ok=True)
    ov = {'jacoco.work_dir': os.path.join(replay_dir, 'jacoco'),
          'jacoco.agent_port': AGENT,
          'keycloak.container_name': INST,
          'keycloak.host_http_port': HTTP,
          'oauth.base_url': f'http://127.0.0.1:{HTTP}',
          'keycloak.health_check_url': f'http://127.0.0.1:{HTTP}/realms/master',
          'keycloak.jvm_args': ['-Xmx1024m', '-Xms256m', '-XX:+UseG1GC']}
    cfg = load_cfg('keycloak', ov)
    cfg_path = os.path.join(replay_dir, 'config_used.json')
    with open(cfg_path, 'w') as f:
        json.dump(cfg, f, indent=2)
    return cfg_path, os.path.join(replay_dir, 'jacoco')


def container_alive():
    r = subprocess.run(['docker', 'ps', '--filter', f'name=^{INST}$',
                        '--format', '{{.Names}}'], capture_output=True, text=True)
    return r.stdout.strip() == INST


def resurrect(cfg_path):
    say(f'instance died — resurrecting {INST}')
    subprocess.run(['docker', 'rm', '-f', INST], capture_output=True)
    if not ensure_up('keycloak', cfg_path, http=HTTP):
        say('resurrection FAILED')
        return False
    return True


def replay_campaign(campaign_dir):
    out_json = os.path.join(campaign_dir, 'replay_coverage.json')
    if os.path.exists(out_json):
        say(f'skip {os.path.basename(campaign_dir)}')
        return
    corpus = os.path.join(campaign_dir, 'corpus_raw')
    files = sorted(os.listdir(corpus))
    cfg_path, jd = build_cfg_path(campaign_dir)
    subprocess.run(['docker', 'rm', '-f', INST], capture_output=True)
    if not ensure_up('keycloak', cfg_path, http=HTTP):
        say(f'ensure_up FAILED for {campaign_dir}')
        return

    from core.coverage import JaCoCoManager
    jm = JaCoCoManager(work_dir=jd)
    jm.max_exec_mb = 400
    n = ok = deaths = 0
    t0 = time.time()
    for i, fn in enumerate(files):
        if not container_alive() and not resurrect(cfg_path):
            break
        path = os.path.join(corpus, fn)
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except Exception:
            continue
        if data:
            n += 1
            ok += int(send_raw('127.0.0.1', HTTP, data))
        if (i + 1) % DUMP_EVERY == 0:
            try:
                jm.dump_coverage_reset(port=AGENT)
            except Exception:
                deaths += 1
                if not resurrect(cfg_path):
                    break
            say(f'{os.path.basename(campaign_dir)}: {i+1}/{len(files)} '
                f'({time.time()-t0:.0f}s, deaths={deaths})')
    try:
        jm.dump_coverage_reset(port=AGENT)
    except Exception:
        pass

    import glob as _g
    jars = [p for p in _g.glob(os.path.join(jd, 'keycloak_lib', '**',
                                            'org.keycloak.keycloak-*.jar'),
                               recursive=True)
            if not any(x in os.path.basename(p) for x in
                       ('sssd-federation', 'kerberos-federation', 'themes',
                        'admin-ui', 'account-ui'))]
    if jars:
        jm.set_classpaths(jars)
    jm.generate_report()
    branch, instr = parse_jacoco_report(jd)
    subprocess.run(['docker', 'rm', '-f', INST], capture_output=True)
    with open(out_json, 'w') as f:
        json.dump({'tool': 'boofuzz', 'target': 'keycloak',
                   'seed': os.path.basename(campaign_dir).split('_s')[-1],
                   'n_cases': n, 'n_ok': ok, 'container_deaths': deaths,
                   'branch_pct': branch, 'instr_pct': instr}, f, indent=2)
    say(f'{os.path.basename(campaign_dir)} -> branch {branch} '
        f'(deaths={deaths}, {time.time()-t0:.0f}s)')


def main():
    base = os.path.join(RESULTS, 'matrix')
    for seed in (1, 2, 3, 4, 5):
        d = os.path.join(base, f'boofuzz_keycloak_s{seed}')
        if os.path.isdir(d):
            replay_campaign(d)
    say('KC KILLSHOT REPLAY COMPLETE')


if __name__ == '__main__':
    main()
