#!/usr/bin/env python3
"""Redo runner for the boofuzz cxf/keycloak campaigns invalidated by the
Sept-24 ENOSPC (internal sqlite db logger filled the disk mid-campaign;
campaigns died ~4h in with no DONE file).

Two dedicated lanes (cxf_oauth, keycloak), seeds 1-5 sequential, DONE-skip.
The main matrix runner has already passed these seeds (its cxf/kc lanes are
finished), so there is no double-run risk; this runner owns them from here.

Usage: nohup python3 run_boofuzz_redo.py > results/boofuzz_redo_nohup.log 2>&1 &
"""
import json
import os
import sys
import threading

HERE = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, HERE)

from common import RESULTS, baseline_campaign, say  # noqa: E402

DEFAULT_LANES = ('cxf_oauth', 'keycloak')
SEEDS = (1, 2, 3, 4, 5)


def lane(target):
    for seed in SEEDS:
        out = os.path.join(RESULTS, 'matrix', f'boofuzz_{target}_s{seed}')
        if os.path.exists(os.path.join(out, 'DONE')):
            say(f'[redo:{target}] s{seed} already DONE, skip')
            continue
        ok = baseline_campaign('boofuzz', target, out, 6.0)
        if ok and not os.path.exists(os.path.join(out, 'DONE')):
            # the campaign script may be reaped past deadline without writing DONE
            with open(os.path.join(out, 'DONE'), 'w') as f:
                json.dump({'note': 'DONE written by runner (campaign ok)'}, f)
        say(f'[redo:{target}] s{seed} end ok={ok}')


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--lanes', default=','.join(DEFAULT_LANES))
    lanes = tuple(ap.parse_args().lanes.split(','))
    threads = [threading.Thread(target=lane, args=(t,), daemon=True)
               for t in lanes]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    say('[redo] all lanes finished')


if __name__ == '__main__':
    main()
