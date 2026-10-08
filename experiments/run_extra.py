#!/usr/bin/env python3
"""Additional-target campaigns (CS revision, Reviewer #3 request): Hydra +
Casdoor, OAuthFuzz only (no baseline comparison — discovery/generality only).

Usage:
  python3 run_extra.py [--duration-h 6] [--seeds 1,2,3]
                       [--targets ory_hydra,casdoor]
"""
import argparse
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS, oauthfuzz_campaign, say  # noqa: E402


def lane(target, duration_h, seeds):
    for seed in seeds:
        out = os.path.join(RESULTS, 'extra', f'oauthfuzz_{target}_s{seed}')
        if os.path.exists(os.path.join(out, 'DONE')):
            continue
        ok = oauthfuzz_campaign(target, out, seed, duration_h=duration_h,
                                arm='full')
        if ok:
            open(os.path.join(out, 'DONE'), 'w').write(
                json.dumps({'rc': 0, 'seed': seed, 'tool': 'oauthfuzz',
                            'duration_h': duration_h}))
        else:
            say(f'[extra {target}] s{seed} FAILED')
            with open(os.path.join(out, 'FAILED'), 'w') as f:
                json.dump({'seed': seed}, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--duration-h', type=float, default=6.0)
    ap.add_argument('--seeds', default='1,2,3')
    ap.add_argument('--targets', default='ory_hydra,casdoor')
    args = ap.parse_args()
    seeds = [int(s) for s in args.seeds.split(',')]
    threads = [threading.Thread(target=lane, args=(t, args.duration_h, seeds))
               for t in args.targets.split(',')]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    say('EXTRA DONE')


if __name__ == '__main__':
    main()
