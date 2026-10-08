#!/usr/bin/env python3
"""Real-data coverage-growth figure (replaces the synthesized curves).

Reads results/matrix/<tool>_<target>_s<seed>/coverage_series.jsonl (Java
targets: live at-target sampling by coverage_sampler.py), averages across
seeds per tool, and renders one panel per target with mean curves. Go
targets without series are skipped with a note (endpoint-only measurement).

Output: results/coverage_curves.pdf (+ .png) — copy into the paper Figures.
"""
import argparse
import json
import os
import re
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.abspath(os.path.dirname(__file__))
TOOLS = ['oauthfuzz', 'boofuzz', 'aflnet']
LABELS = {'oauthfuzz': 'OAuthFuzz', 'boofuzz': 'BooFuzz', 'aflnet': 'AFLNet',
          'stateafl': 'StateAFL', 'chatafl': 'ChatAFL', 'sdfuzz': 'SDFuzz'}


def read_series(path):
    pts = []
    if not os.path.exists(path):
        return pts
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            v = r.get('branch_pct')
            if v is None:
                v = r.get('covdata_pct')
            if v is not None and r.get('t_h') is not None:
                pts.append((float(r['t_h']), float(v)))
    return sorted(pts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', default=os.path.join(HERE, 'results', 'matrix'))
    ap.add_argument('--out', default=os.path.join(HERE, 'results', 'coverage_curves'))
    args = ap.parse_args()

    per = defaultdict(lambda: defaultdict(list))  # target -> tool -> [series]
    for name in sorted(os.listdir(args.results)):
        g = re.match(r'^(aflnet|boofuzz|oauthfuzz)_(.+)_s(\d+)$', name)
        if not g:
            continue
        tool, target = g.group(1), g.group(2)
        pts = read_series(os.path.join(args.results, name, 'coverage_series.jsonl'))
        if pts:
            per[target][tool].append(pts)

    targets = [t for t in ('keycloak', 'authelia', 'cxf_oauth') if t in per]
    if not targets:
        print('no coverage_series.jsonl found yet — run campaigns first')
        return
    fig, axes = plt.subplots(1, len(targets), figsize=(5 * len(targets), 3.6))
    if len(targets) == 1:
        axes = [axes]
    for ax, target in zip(axes, targets):
        for tool in TOOLS:
            series = per[target].get(tool, [])
            if not series:
                continue
            # resample to a common 15-min grid, then average across seeds
            grid = [i * 0.25 for i in range(0, int(6 / 0.25) + 1)]
            traces = []
            for pts in series:
                xs = [p[0] for p in pts]
                ys = [p[1] for p in pts]
                trace = []
                for g in grid:
                    val = None
                    for x, y in zip(xs, ys):
                        if x <= g:
                            val = y
                    trace.append(val if val is not None else (ys[0] if ys else 0))
                # monotonic fill-forward
                m = 0
                for i, v in enumerate(trace):
                    m = max(m, v)
                    trace[i] = m
                traces.append(trace)
            mean = [sum(t[i] for t in traces) / len(traces) for i in range(len(grid))]
            ax.plot(grid, mean, label=LABELS.get(tool, tool), linewidth=2)
        ax.set_title(target.replace('cxf_oauth', 'Apache CXF').capitalize()
                     if target != 'cxf_oauth' else 'Apache CXF')
        ax.set_xlabel('Time (hours)')
        ax.set_ylabel('Branch coverage (%)')
        ax.grid(alpha=0.3)
        ax.legend(fontsize=8)
    fig.tight_layout()
    for ext in ('pdf', 'png'):
        fig.savefig(f'{args.out}.{ext}', dpi=150, bbox_inches='tight')
    print(f'wrote {args.out}.pdf/.png for targets: {targets}')
    skipped = [t for t in ('keycloak', 'authelia', 'cxf_oauth') if t not in per]
    if skipped:
        print(f'note: no time series for {skipped} (Go endpoint-only measurement '
              f'or campaigns not finished)')


if __name__ == '__main__':
    main()
