#!/usr/bin/env python3
"""Main comparison matrix (CS revision): 3 targets x 3 tools x 5 seeds x 6h.

One lane per target (fixed port map, no intra-target concurrency). Each lane
runs, sequentially: oauthfuzz seeds 1-5, aflnet seeds 1-5, boofuzz seeds 1-5
(15 campaigns x 6h per lane). DONE markers make it resumable.

Usage:
  python3 run_matrix.py [--duration-h 6] [--seeds 1,2,3,4,5]
                        [--targets cxf_oauth,keycloak,authelia]
                        [--tools oauthfuzz,aflnet,boofuzz]
"""
import argparse
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import RESULTS, TARGETS, baseline_campaign, oauthfuzz_campaign, prune_campaign_dir, say  # noqa: E402


def lane(target, duration_h, seeds, tools):
    cfg = TARGETS[target]
    for tool in tools:
        for seed in seeds:
            out = os.path.join(RESULTS, 'matrix', f'{tool}_{target}_s{seed}')
            if os.path.exists(os.path.join(out, 'DONE')):
                continue
            if tool == 'oauthfuzz':
                ok = oauthfuzz_campaign(target, out, seed, duration_h=duration_h,
                                        arm='full')
            else:
                ok = baseline_campaign(tool, target, out, duration_h=duration_h)
            if ok:
                open(os.path.join(out, 'DONE'), 'w').write(
                    json.dumps({'rc': 0, 'seed': seed, 'tool': tool,
                                'duration_h': duration_h}))
                prune_campaign_dir(out, target)
            else:
                say(f'[lane {target}] {tool} s{seed} FAILED — continuing')
                with open(os.path.join(out, 'FAILED'), 'w') as f:
                    json.dump({'tool': tool, 'seed': seed}, f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--duration-h', type=float, default=6.0)
    ap.add_argument('--seeds', default='1,2,3,4,5')
    ap.add_argument('--targets', default='cxf_oauth,keycloak,authelia')
    ap.add_argument('--tools', default='oauthfuzz,aflnet,boofuzz')
    args = ap.parse_args()
    os.makedirs(RESULTS, exist_ok=True)
    seeds = [int(s) for s in args.seeds.split(',')]
    threads = [threading.Thread(target=lane,
                                args=(t, args.duration_h, seeds,
                                      args.tools.split(',')))
               for t in args.targets.split(',')]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    say('MATRIX DONE')


if __name__ == '__main__':
    main()
