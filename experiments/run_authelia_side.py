#!/usr/bin/env python3
"""Side lane: the five boofuzz authelia campaigns on a SECOND authelia-cover
instance (http 9092), in REVERSE seed order.

Why: the Sept-21 relative-bind bug invalidated all five aflnet_authelia
campaigns; the main matrix runner's authelia lane now redoes those first
(~30h) before reaching boofuzz. This side lane runs the boofuzz half in
parallel; DONE markers make the main runner skip whatever finishes here.
Reverse order (s5->s2) keeps the two lanes from ever meeting inside the same
campaign directory: the main lane only reaches boofuzz after its five aflnet
redos (~28h), by which time this lane has finished s2-s5 (~24h). Sept-24:
original s5-s3 runs died ~4h in from the ENOSPC — all four are redone.

Usage: nohup python3 run_authelia_side.py > results/authelia_side_nohup.log &
"""
import json
import os
import sys
import time

HERE = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, HERE)

from common import RESULTS, baseline_campaign, say  # noqa: E402

SEEDS = (5, 4, 3, 2)
INST = {'http_port': 9092, 'aflnet_port': 26021}


def main():
    for seed in SEEDS:
        out = os.path.join(RESULTS, 'matrix', f'boofuzz_authelia_s{seed}')
        if os.path.exists(os.path.join(out, 'DONE')):
            say(f'[side] {os.path.basename(out)} already DONE, skip')
            continue
        ok = baseline_campaign('boofuzz', 'authelia', out, 6.0, inst=INST)
        if ok and not os.path.exists(os.path.join(out, 'DONE')):
            with open(os.path.join(out, 'DONE'), 'w') as f:
                json.dump({'note': 'DONE written by runner (campaign ok)'}, f)
        say(f'[side] boofuzz_authelia_s{seed} end ok={ok}')


if __name__ == '__main__':
    main()
