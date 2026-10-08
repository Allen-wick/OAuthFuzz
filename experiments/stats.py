#!/usr/bin/env python3
"""Statistics for the comparison and ablation tables.

- Exact two-sided Mann-Whitney U (5v5; ported from the OAuthLancer
  aggregate_ablation.py implementation, average-rank + recursion counts).
- mean / std over seeds.

Produces:
  results/coverage_stats.json  (matrix: per tool-target mean±std, MWU p vs
                                the strongest baseline, significance flags)
  results/ablation_stats.json  (per arm: coverage mean±std, #defects
                                (distinct oracle types), TTFD minutes)
  results/ttfd.json            (per-run time-to-first-defect, incl. matrix)

Usage:
  python3 stats.py [--results results]
"""
import argparse
import json
import math
import os
import re
from collections import defaultdict

HERE = os.path.abspath(os.path.dirname(__file__))


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def mann_whitney_u(x, y):
    """Exact two-sided p for small n (5v5); returns (U, p)."""
    nx, ny = len(x), len(y)
    if not x or not y:
        return None, None
    ranks = sorted([(v, 'x') for v in x] + [(v, 'y') for v in y],
                   key=lambda t: t[0])
    i = 0
    ranked = []
    while i < len(ranks):
        j = i
        while j < len(ranks) and ranks[j][0] == ranks[i][0]:
            j += 1
        avg = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranked.append((avg, ranks[k][1]))
        i = j
    rank_sum_x = sum(r for r, t in ranked if t == 'x')
    u1 = rank_sum_x - nx * (nx + 1) / 2.0
    u = min(u1, nx * ny - u1)
    try:
        from math import comb

        def count_dist(u_target, a, b):
            if a == 0 or b == 0:
                return 1 if u_target == 0 else 0
            if u_target < 0:
                return 0
            return (count_dist(u_target - b, a - 1, b) +
                    count_dist(u_target, a, b - 1))
        total = comb(nx + ny, nx)
        n_le = sum(count_dist(k, nx, ny) for k in range(0, int(u) + 1))
        p = min(1.0, 2.0 * n_le / total)
    except Exception:
        p = None
    return u, p


def mean_std(xs):
    xs = [x for x in xs if x is not None]
    n = len(xs)
    m = sum(xs) / n if n else None
    v = sum((x - m) ** 2 for x in xs) / (n - 1) if n > 1 else 0.0
    return m, (math.sqrt(v) if m is not None else None)


def camp_metrics(campaign_dir):
    """Coverage + defects + TTFD for one OAuthFuzz campaign dir."""
    m = {'dir': os.path.basename(campaign_dir)}
    summ = os.path.join(campaign_dir, 'fuzzing_summary.json')
    if os.path.exists(summ):
        try:
            with open(summ) as f:
                s = json.load(f)
            m['peak_coverage'] = s.get('fuzzing_session', {}).get('peak_coverage_percentage')
        except (json.JSONDecodeError, OSError):
            # e.g. no_ep_s5's summary was zeroed by the 09-22 host crash
            # (all-NUL blocks); replay_coverage.json is the authoritative
            # coverage record for that campaign
            m['peak_coverage'] = None
    rj = os.path.join(campaign_dir, 'replay_coverage.json')
    if os.path.exists(rj):
        with open(rj) as f:
            r = json.load(f)
        m['replay_branch'] = r.get('branch_pct')
        m['replay_covdata'] = r.get('covdata_pct')
    fj = os.path.join(campaign_dir, 'coverage_final.json')
    if os.path.exists(fj):
        with open(fj) as f:
            m['covdata_pct'] = json.load(f).get('covdata_pct')

    cases = read_jsonl(os.path.join(campaign_dir, 'interesting_cases.jsonl'))
    start = None
    sj = os.path.join(campaign_dir, 'start_epoch.json')
    if os.path.exists(sj):
        with open(sj) as f:
            start = json.load(f).get('start_epoch')
    defect_types = set()
    first_ts = None
    for c in cases:
        for o in c.get('oracles', []):
            if o.get('type') not in ('POTENTIAL_CRASH',):
                defect_types.add(o.get('type'))
        if c.get('oracles') and first_ts is None:
            first_ts = c.get('timestamp')
        if c.get('crash_detail') and first_ts is None:
            first_ts = c.get('timestamp')
    m['n_cases'] = len(cases)
    m['n_defect_types'] = len(defect_types)
    m['defect_types'] = sorted(defect_types)
    if first_ts and start:
        m['ttfd_min'] = round((first_ts - start) / 60.0, 1)
    return m


def coverage_stats(results_dir):
    matrix = os.path.join(results_dir, 'matrix')
    per = defaultdict(lambda: defaultdict(list))
    if os.path.isdir(matrix):
        for name in sorted(os.listdir(matrix)):
            d = os.path.join(matrix, name)
            g = re.match(r'^(aflnet|boofuzz|oauthfuzz)_(.+)_s(\d+)$', name)
            if not g or not os.path.isdir(d):
                continue
            tool, target, seed = g.group(1), g.group(2), g.group(3)
            rj = os.path.join(d, 'replay_coverage.json')
            cov = None
            if os.path.exists(rj):
                with open(rj) as f:
                    r = json.load(f)
                cov = r.get('branch_pct', r.get('covdata_pct'))
            if cov is None:
                fj = os.path.join(d, 'coverage_final.json')
                if os.path.exists(fj):
                    with open(fj) as f:
                        cov = json.load(f).get('covdata_pct')
            if cov is not None:
                per[target][tool].append(cov)

    # The oauthfuzz matrix campaign dirs were lost in the Sept-27 emergency
    # cleanup; their per-seed replay values were preserved in this side file
    # (transcribed from the original aggregate) — merge any rows the scan
    # could not reconstruct.
    preserved = os.path.join(results_dir, 'oauthfuzz_values_preserved.json')
    if os.path.exists(preserved):
        with open(preserved) as f:
            pv = json.load(f)
        for target, values in pv.items():
            if target.startswith('_'):
                continue
            if not per.get(target, {}).get('oauthfuzz'):
                per[target]['oauthfuzz'] = list(values)

    out = {}
    for target, tools in per.items():
        out[target] = {}
        means = {}
        for tool, vals in tools.items():
            m, s = mean_std(vals)
            out[target][tool] = {'runs': len(vals), 'mean': round(m, 2),
                                 'std': round(s, 2) if s is not None else None,
                                 'values': vals}
            means[tool] = m
        baselines = {t: v for t, v in means.items() if t != 'oauthfuzz'}
        if 'oauthfuzz' in means and baselines:
            best = max(baselines, key=baselines.get)
            u, p = mann_whitney_u(tools['oauthfuzz'], tools[best])
            out[target]['_test'] = {
                'best_baseline': best,
                'U': u, 'p_exact_two_sided': p,
                'significant_alpha0.05': (p is not None and p < 0.05),
                'relative_improvement_pct': round(
                    100.0 * (means['oauthfuzz'] / baselines[best] - 1.0), 1)}
    path = os.path.join(results_dir, 'coverage_stats.json')
    with open(path, 'w') as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))
    return path


def ablation_stats(results_dir):
    abl = os.path.join(results_dir, 'ablation')
    per = defaultdict(dict)
    ttfd_all = {}
    if os.path.isdir(abl):
        for name in sorted(os.listdir(abl)):
            d = os.path.join(abl, name)
            g = re.match(r'^(baseline|no_ep|no_fb|full|no_cve)_s(\d+)$', name)
            if not g or not os.path.isdir(d):
                continue
            arm, seed = g.group(1), g.group(2)
            per[arm][seed] = camp_metrics(d)
            if per[arm][seed].get('ttfd_min') is not None:
                ttfd_all[f'{arm}_s{seed}'] = per[arm][seed]['ttfd_min']
    out = {}
    for arm, seeds in per.items():
        covs = [m.get('peak_coverage') or m.get('replay_branch') or m.get('covdata_pct')
                for m in seeds.values()]
        m_cov, s_cov = mean_std(covs)
        defects = set()
        ttfd = []
        for mm in seeds.values():
            defects.update(mm.get('defect_types', []))
            if mm.get('ttfd_min') is not None:
                ttfd.append(mm['ttfd_min'])
        m_t, s_t = mean_std(ttfd)
        out[arm] = {
            'runs': len(seeds),
            'coverage_mean': round(m_cov, 2) if m_cov is not None else None,
            'coverage_std': round(s_cov, 2) if s_cov is not None else None,
            'n_defect_types': len(defects),
            'defect_types': sorted(defects),
            'ttfd_min_mean': round(m_t, 1) if m_t is not None else None,
            'ttfd_min_std': round(s_t, 1) if s_t is not None else None,
            'per_seed': {s: {k: v for k, v in mm.items() if k != 'defect_types'}
                         for s, mm in seeds.items()}}
    # pairwise MWU vs full on coverage
    if 'full' in out:
        full_covs = []
        for seed, mm in per.get('full', {}).items():
            v = mm.get('peak_coverage') or mm.get('replay_branch') or mm.get('covdata_pct')
            if v is not None:
                full_covs.append(v)
        for arm in out:
            if arm == 'full':
                continue
            arm_covs = []
            for seed, mm in per.get(arm, {}).items():
                v = mm.get('peak_coverage') or mm.get('replay_branch') or mm.get('covdata_pct')
                if v is not None:
                    arm_covs.append(v)
            u, p = mann_whitney_u(full_covs, arm_covs)
            out[arm]['_mwu_vs_full'] = {'U': u, 'p_exact_two_sided': p}

    path = os.path.join(results_dir, 'ablation_stats.json')
    with open(path, 'w') as f:
        json.dump(out, f, indent=2)
    with open(os.path.join(results_dir, 'ttfd.json'), 'w') as f:
        json.dump(ttfd_all, f, indent=2)
    print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != 'per_seed'}
                      for k, v in out.items()}, indent=2))
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', default=os.path.join(HERE, 'results'))
    args = ap.parse_args()
    coverage_stats(args.results)
    ablation_stats(args.results)


if __name__ == '__main__':
    main()
