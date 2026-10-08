#!/usr/bin/env python3
"""Ablation matrix: Keycloak x 5 arms x 5 seeds x 6h.

Arms (switch semantics implemented in core/fuzzer.py, 2026-09):
  baseline : disable_ep + disable_feedback          (random, no knowledge)
  no_ep    : disable_ep                             (+DG only)
  no_fb    : disable_feedback                       (+EP only)
  full     : all switches off                       (Full OAuthFuzz)
  no_cve   : disable_cve_patterns                   (Full minus CVE knowledge)

Runs `--lanes` CONCURRENT isolated Keycloak instances (distinct container
names / host HTTP ports / JaCoCo agent ports), distributing the 25 campaigns
round-robin over the lanes. Resumable via DONE markers.

Usage:
  python3 run_ablation.py [--lanes 3] [--duration-h 6] [--seeds 1,2,3,4,5]
                          [--arms baseline,no_ep,no_fb,full,no_cve]
                          [--target keycloak]
"""
import argparse
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS, TARGETS, oauthfuzz_campaign, prune_campaign_dir, say  # noqa: E402

# Instance allocation: lane i -> (container, host_http_port, agent_port)
# JVM heap capped for multi-instance concurrency (host has 16GB RAM shared
# with the matrix lanes and other resident stacks).
def inst_for(lane_i, target):
    return {
        'container': f'{target}-abl-lane{lane_i}',
        'http_port': 28080 + lane_i,
        'agent_port': 26300 + lane_i * 10,
        'jvm_args': ['-Xmx1536m', '-Xms512m', '-XX:+UseG1GC',
                     '-XX:MaxGCPauseMillis=200'],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lanes', type=int, default=3)
    ap.add_argument('--duration-h', type=float, default=6.0)
    ap.add_argument('--seeds', default='1,2,3,4,5')
    ap.add_argument('--arms', default='baseline,no_ep,no_fb,full,no_cve')
    ap.add_argument('--target', default='keycloak')
    args = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)

    seeds = [int(s) for s in args.seeds.split(',')]
    arms = args.arms.split(',')
    jobs = [(arm, seed) for arm in arms for seed in seeds]  # 25 jobs
    lanes = [[] for _ in range(args.lanes)]
    for i, job in enumerate(jobs):
        lanes[i % args.lanes].append(job)

    def run_lane(lane_i, jobs_i):
        inst = inst_for(lane_i, args.target)
        for arm, seed in jobs_i:
            out = os.path.join(RESULTS, 'ablation', f'{arm}_s{seed}')
            if os.path.exists(os.path.join(out, 'DONE')):
                continue
            ok = oauthfuzz_campaign(args.target, out, seed,
                                    duration_h=args.duration_h,
                                    arm=arm, inst=inst)
            if ok:
                open(os.path.join(out, 'DONE'), 'w').write(
                    json.dumps({'rc': 0, 'arm': arm, 'seed': seed,
                                'duration_h': args.duration_h,
                                'instance': inst}))
                prune_campaign_dir(out, args.target)
            else:
                say(f'[abl-lane{lane_i}] {arm} s{seed} FAILED')
                with open(os.path.join(out, 'FAILED'), 'w') as f:
                    json.dump({'arm': arm, 'seed': seed, 'instance': inst}, f)

    threads = [threading.Thread(target=run_lane, args=(i, l))
               for i, l in enumerate(lanes)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    say('ABLATION DONE')


if __name__ == '__main__':
    main()
