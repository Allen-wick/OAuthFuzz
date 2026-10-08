#!/usr/bin/env python3
"""Strict-vs-legacy Oracle pair (oracle precision experiment).

Two Keycloak OAuthFuzz campaigns, identical in every respect except the
oracle's compliance baseline:
  strict_s1  : default oracle (OAuth 2.1-era expectations, incl. PKCE)
  legacy_s1  : OAUTH_FUZZ_ORACLE_LEGACY=1 (RFC 6749 baseline, no PKCE alerts)

2h each — the precision metric is alert-level and stabilizes long before
coverage saturation.

Usage: nohup python3 run_oracle_pair.py > results/oracle_pair.log 2>&1 &
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, HERE)

from common import RESULTS, ensure_up, load_cfg, say  # noqa: E402

PAIR = [('strict_s1', False), ('legacy_s1', True)]
HTTP = 38083
AGENT = 27303
INST = 'kc-oracle-pair'


def campaign(name, legacy, duration_h=2.0):
    out = os.path.join(RESULTS, 'oracle_pair', name)
    os.makedirs(out, exist_ok=True)
    if os.path.exists(os.path.join(out, 'DONE')):
        say(f'skip {name}')
        return
    ov = {'output_dir': out,
          'fuzzing.seed': 7,
          'fuzzing.save_interesting_cases': True,
          'fuzzing.budget_protocol_steps': 0,
          'fuzzing.dump_every_n': 200,
          'jacoco.work_dir': os.path.join(out, 'jacoco'),
          'jacoco.agent_port': AGENT,
          'keycloak.container_name': INST,
          'keycloak.host_http_port': HTTP,
          'oauth.base_url': f'http://127.0.0.1:{HTTP}',
          'keycloak.health_check_url': f'http://127.0.0.1:{HTTP}/realms/master',
          'keycloak.jvm_args': ['-Xmx1024m', '-Xms256m', '-XX:+UseG1GC']}
    cfg = load_cfg('keycloak', ov)
    cfg_path = os.path.join(out, 'config_used.json')
    with open(cfg_path, 'w') as f:
        json.dump(cfg, f, indent=2)
    if not ensure_up('keycloak', cfg_path, http=HTTP):
        say(f'ensure_up failed for {name}')
        return
    env = dict(os.environ)
    env['OAUTH_FUZZ_GO_SNAPSHOT'] = '0'
    if legacy:
        env['OAUTH_FUZZ_ORACLE_LEGACY'] = '1'
    cmd = [sys.executable, os.path.join(HERE, '..', '..', '..',
                                        'run_oauth_fuzzing.py'),
           '--config', cfg_path, '--mode', 'aflnet', '--adapter', 'boofuzz',
           '--iterations', str(10 ** 9)]
    with open(os.path.join(out, 'start_epoch.json'), 'w') as f:
        json.dump({'start_epoch': time.time()}, f)
    t0 = time.time()
    proc = subprocess.Popen(cmd, cwd=os.path.abspath(os.path.join(HERE, '..', '..', '..')),
                            env=env,
                            stdout=open(os.path.join(out, 'run.log'), 'w'),
                            stderr=subprocess.STDOUT)
    while proc.poll() is None and time.time() - t0 < duration_h * 3600:
        time.sleep(30)
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(300)
        except subprocess.TimeoutExpired:
            proc.kill()
    with open(os.path.join(out, 'DONE'), 'w') as f:
        json.dump({'rc': proc.poll(), 'legacy': legacy,
                   'duration_h': duration_h}, f)
    say(f'{name} done rc={proc.poll()}')


def main():
    for name, legacy in PAIR:
        campaign(name, legacy)
    say('ORACLE PAIR COMPLETE')


if __name__ == '__main__':
    main()
