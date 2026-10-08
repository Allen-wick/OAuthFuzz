#!/usr/bin/env python3
"""Real-data coverage figure (box plots over seeds, replay protocol).

Replaces the original growth-curve figure: the OAuthFuzz in-run series were
lost in the Sept-27 emergency disk cleanup, and with n=5 seeds per cell a
box plot over the replay-measured values matches the exact-MWU narrative
better anyway.

Panels: one per target (OAuth-relevant branch %; authelia panel shows Go
statement %) + one ablation panel (Keycloak, five arms).

Output: results/coverage_box.pdf (+ .png)
"""
import json
import os
from collections import defaultdict

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402

HERE = os.path.abspath(os.path.dirname(__file__))
RESULTS = os.path.join(HERE, 'results')
TOOLS = ['aflnet', 'boofuzz', 'oauthfuzz']
LABELS = {'oauthfuzz': 'OAuthFuzz', 'boofuzz': 'BooFuzz', 'aflnet': 'AFLNet'}
TARGETS = [('authelia', 'Authelia\n(Go stmt. %)'),
           ('cxf_oauth', 'Apache CXF\n(JVM branch %)'),
           ('keycloak', 'Keycloak\n(JVM branch %)')]
ARMS = ['baseline', 'no_ep', 'no_fb', 'no_cve', 'full']
ARM_LABELS = {'baseline': 'Baseline\n(no EP, no FB)', 'no_ep': '+DG only',
              'no_fb': '+EP only', 'no_cve': 'Full$-$CVE', 'full': 'Full'}


def matrix_values():
    """vals[target][tool] = [5 replay numbers].

    Primary source: results/coverage_stats.json (the aggregate record —
    per-campaign replay_coverage.json files for the oauthfuzz rows were lost
    in the Sept-27 emergency cleanup, but their values were aggregated here
    first). Per-campaign files fill any cells the aggregate lacks (e.g. the
    pending boofuzz_keycloak replays once they run)."""
    vals = defaultdict(lambda: defaultdict(list))
    cs_path = os.path.join(RESULTS, 'coverage_stats.json')
    if os.path.exists(cs_path):
        with open(cs_path) as f:
            cs = json.load(f)
        for tgt, tools in cs.items():
            if not isinstance(tools, dict):
                continue
            for t, m in tools.items():
                if isinstance(m, dict) and m.get('values'):
                    vals[tgt][t] = [round(v, 2) for v in m['values']]
    base = os.path.join(RESULTS, 'matrix')
    for name in os.listdir(base):
        rj = os.path.join(base, name, 'replay_coverage.json')
        if not os.path.exists(rj):
            continue
        tool_full, _, _seed = name.rpartition('_s')
        tname = tool_full.partition('_')[2]
        with open(rj) as f:
            r = json.load(f)
        v = r.get('branch_pct')
        if v is None:
            v = r.get('covdata_pct')
        tool = tool_full.split('_')[0]
        if v is not None and tname and not vals[tname].get(tool):
            # fill ONLY cells absent from the aggregate (e.g. later replays)
            vals[tname][tool].append(round(v, 2))
    return vals


def ablation_values():
    vals = defaultdict(list)
    base = os.path.join(RESULTS, 'ablation')
    for name in os.listdir(base):
        rj = os.path.join(base, name, 'replay_coverage.json')
        if not os.path.exists(rj):
            continue
        arm = name.rpartition('_s')[0]
        with open(rj) as f:
            r = json.load(f)
        v = r.get('branch_pct')
        if v is not None:
            vals[arm].append(round(v, 2))
    return vals


def main():
    mv = matrix_values()
    av = ablation_values()
    fig, axes = plt.subplots(1, 4, figsize=(13, 3.1), gridspec_kw={'width_ratios': [1, 1, 1, 1.25]})

    for ax, (tgt, title) in zip(axes[:3], TARGETS):
        data, labels = [], []
        for t in TOOLS:
            if mv[tgt].get(t):
                data.append(mv[tgt][t])
                labels.append(LABELS[t])
        bp = ax.boxplot(data, labels=labels, patch_artist=True, widths=0.55)
        for patch, color in zip(bp['boxes'], ['#9dbbd8', '#f0b27a', '#c0392b']):
            patch.set_facecolor(color)
            patch.set_alpha(0.75)
        for med in bp['medians']:
            med.set_color('black')
        ax.set_title(title, fontsize=9)
        ax.tick_params(axis='x', labelsize=7.5, rotation=0)
        ax.tick_params(axis='y', labelsize=7.5)
        ax.set_ylabel('coverage (%)' if tgt == 'authelia' else '', fontsize=8)
        ax.grid(axis='y', alpha=0.3)

    ax = axes[3]
    data = [av[a] for a in ARMS if av.get(a)]
    labels = [ARM_LABELS[a] for a in ARMS if av.get(a)]
    bp = ax.boxplot(data, labels=labels, patch_artist=True, widths=0.6)
    for patch in bp['boxes']:
        patch.set_facecolor('#bdc3c7')
        patch.set_alpha(0.7)
    bp['boxes'][-1].set_facecolor('#c0392b')
    bp['boxes'][-1].set_alpha(0.75)
    for med in bp['medians']:
        med.set_color('black')
    ax.set_title('Keycloak ablation\n(JVM branch %)', fontsize=9)
    ax.tick_params(axis='x', labelsize=7, rotation=20)
    ax.tick_params(axis='y', labelsize=7.5)
    ax.grid(axis='y', alpha=0.3)

    fig.suptitle('Post-hoc corpus-replay coverage (5 seeds per cell; identical instrumentation for all tools)',
                 fontsize=9.5, y=1.04)
    fig.tight_layout()
    out = os.path.join(RESULTS, 'coverage_box')
    fig.savefig(out + '.pdf', bbox_inches='tight')
    fig.savefig(out + '.png', dpi=180, bbox_inches='tight')
    print('wrote', out + '.pdf')
    for tgt in mv:
        print(tgt, {t: mv[tgt][t] for t in mv[tgt]})


if __name__ == '__main__':
    main()
