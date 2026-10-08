#!/usr/bin/env python3
"""Replay ablation corpora (OAuthFuzz interesting cases) on a pristine
Keycloak instance — the same post-hoc protocol as the matrix, so the
ablation table's coverage uses ONE consistent measurement basis. Also
recovers no_ep_s5, whose fuzzing_summary.json was zeroed by the Sept-22
host crash (all-NUL page-cache loss): its replay_coverage.json becomes the
authoritative coverage record.

Sequential; one replay instance (keycloak-abl-replay :38081, agent 27301).
Usage: nohup python3 replay_ablation.py > results/replay_ablation.log 2>&1 &
"""
import glob as _g
import json
import os
import subprocess
import sys
import time

HERE = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, '..', '..', '..')))

from common import RESULTS, ensure_up, load_cfg, say  # noqa: E402
from replay_corpus import SutReplayer, parse_jacoco_report  # noqa: E402

ABL = os.path.join(RESULTS, 'ablation')
INST = 'keycloak-abl-replay'
HTTP = 38081
AGENT = 27301


def replay_arm_dir(d):
    out_json = os.path.join(d, 'replay_coverage.json')
    if os.path.exists(out_json):
        say(f'skip {os.path.basename(d)} (already replayed)')
        return
    cases_p = os.path.join(d, 'interesting_cases.jsonl')
    if not os.path.exists(cases_p):
        say(f'no cases in {os.path.basename(d)}')
        return
    replay_dir = os.path.join(d, 'replay_instance')
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

    subprocess.run(['docker', 'rm', '-f', INST], capture_output=True)
    if not ensure_up('keycloak', cfg_path, http=HTTP):
        say(f'ensure_up FAILED for {os.path.basename(d)}')
        return

    rep = SutReplayer(cfg_path)
    n = ok = 0
    t0 = time.time()
    with open(cases_p) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                case = json.loads(line)
            except Exception:
                continue
            n += 1
            ok += int(rep.replay_case(case))
    say(f'{os.path.basename(d)}: {ok}/{n} cases in {time.time()-t0:.0f}s')

    from core.coverage import JaCoCoManager
    jd = os.path.join(replay_dir, 'jacoco')
    jm = JaCoCoManager(work_dir=jd)
    try:
        jm.dump_coverage(port=AGENT)
    except Exception as e:
        say(f'final dump failed: {e}')
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
        json.dump({'arm_dir': os.path.basename(d), 'n_cases': n, 'n_ok': ok,
                   'branch_pct': branch, 'instr_pct': instr}, f, indent=2)
    say(f'{os.path.basename(d)} -> branch {branch}')


def main():
    for name in sorted(os.listdir(ABL)):
        d = os.path.join(ABL, name)
        if os.path.isdir(d):
            replay_arm_dir(d)
    say('ABLATION REPLAY BATCH COMPLETE')


if __name__ == '__main__':
    main()
