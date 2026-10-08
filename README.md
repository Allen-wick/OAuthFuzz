# OAuthFuzz

OAuthFuzz is a protocol-aware adaptive fuzzing framework for OAuth 2.0
implementations. It profiles the target's endpoints, generates structurally
valid protocol sequences with structure-preserving and CVE-derived mutations,
steers exploration with live branch-coverage feedback plus protocol heuristics,
isolates state at the session level, and flags non-crashing logic flaws with a
three-tier security oracle.

This repository contains the framework source, the per-target configurations,
the campaign/replay/statistics pipeline, and the disclosure evidence for the
vulnerabilities found with it.

## Contents

```
framework/            OAuthFuzz core
  core/               config, coverage (JaCoCo/Go), mutation adapters, oracles
  OAuthMapper/        SUT/protocol engine (symbol stepping, sessions)
  protocol/           per-target protocol mixins + attack symbols
  targets_manager/    deployment/session adapters (one manager per target)
  run_oauth_fuzzing.py  CLI entry point
configs/              per-target run configurations
experiments/          campaign pipeline
  common.py             campaign wrappers, isolation, fairness measures
  run_matrix.py         main comparison matrix (targets x tools x seeds)
  run_ablation.py       ablation arms on Keycloak
  run_extra.py          Hydra + Casdoor discovery campaigns
  run_oracle_pair.py    strict/legacy oracle-baseline pair campaigns
  replay_corpus.py      post-hoc corpus-replay coverage protocol
  stats.py              exact Mann-Whitney U + mean/std aggregation
  plot_coverage.py      coverage-growth figures
  bench_reset.py        state-reset decomposition benchmark
  bench_overhead.py     instrumentation-overhead benchmark
  aflnet/               one-shot relay + per-target AFLNet seeds
  boofuzz_campaign.py   BooFuzz baseline (raw-corpus logging)
  coverage_sampler.py   live at-target coverage sampling (Java)
  results/              curated per-campaign evidence (see below)
disclosure/           verbatim evidence for disclosed findings (see disclosure/MANIFEST.md)
README.md             this file
```

## Quick start (smoke)

```bash
# 1. Start a 4-minute smoke campaign against Keycloak (needs Docker)
cd experiments
python3 -c "
from common import oauthfuzz_campaign
oauthfuzz_campaign('keycloak', 'results/smoke/demo', seed=1, dry_smoke=4/60)
"

# 2. Replay the produced corpus on a pristine instrumented instance
python3 replay_corpus.py --campaign results/smoke/demo

# 3. Aggregate statistics
python3 stats.py
```

## Reproducing the evaluation

Requirements: Docker; Python 3.8+ with `requests`, `matplotlib`; Java 11+ and
Maven (CXF target build); Go 1.20+ (Go target coverage builds); AFLNet
checked out and built (`~/tools/aflnet`); BooFuzz 0.4.2.

```bash
cd experiments
python3 aflnet/build_seeds.py                    # per-target baseline seeds
python3 run_matrix.py --duration-h <hours>       # main comparison matrix
python3 run_ablation.py --lanes 3                # ablation campaigns
python3 run_extra.py                             # Hydra + Casdoor
for d in results/matrix/*/; do python3 replay_corpus.py --campaign "$d"; done
python3 replay_corpus.py --aggregate results/matrix
python3 stats.py                                 # tables + significance tests
python3 plot_coverage.py                         # coverage figure
python3 bench_reset.py                           # reset decomposition
python3 bench_overhead.py --instrumented-url http://127.0.0.1:8080
```

## Per-campaign evidence

Every campaign directory contains: `config_used.json` (exact configuration
including ablation switches and seed), `start_epoch.json`, `run.log`,
`fuzzing_summary.json`, `interesting_cases.jsonl` (sequence + overrides +
oracle verdicts — the replay corpus), `coverage_series.jsonl` (Java live
sampling) or `coverage_final.json` (Go endpoint measurement),
`replay_coverage.json` (post-hoc replay result), and a `DONE` marker.

## Statistics

Exact two-sided Mann-Whitney U (rank-count recursion; appropriate at n=5 vs
5), mean ± std across seeds; significance threshold α = 0.05. See
`experiments/stats.py`.

## Disclosure evidence

`disclosure/` contains verbatim request/response captures, PoC scripts, and
container logs for the publicly disclosed vulnerabilities (see
`disclosure/MANIFEST.md`). Findings still under coordinated disclosure are
represented by sanitized descriptions.

## Ablation switches

`fuzzing.disable_ep` (endpoint profiling off: generic RFC seeds, no
capability scrub), `fuzzing.disable_cve_patterns` (historical-CVE mutation
heuristics off), `fuzzing.disable_feedback` (dynamic guidance off:
round-robin, frozen corpus/weights). Arms used in our evaluation:
baseline = ep+feedback off; no_ep = "+DG only"; no_fb = "+EP only";
no_cve = "Full − CVE"; full = all on.
