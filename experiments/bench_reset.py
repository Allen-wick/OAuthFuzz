#!/usr/bin/env python3
"""RQ4 timing decomposition benchmark (resolves reviewer 2b).

Three separately-timed components, N sequences each:

  A. session-reset-only : N x OAuthSUT.reset() (fresh requests.Session,
     new nonce/state/PKCE params, credential purge) — the pure application-
     level reset overhead.
  B. end-to-end light sequence : N x (reset + one Authorize step) — the
     realistic per-sequence cost including network round-trip.
  C. container restart cycle : M x (docker start + health-wait + stop) —
     the traditional coarse-grained reset (M small; per-cycle time is what
     matters).

Writes results/bench_reset.json. Run against a live target started via the
manager (Java target recommended: keycloak).
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.abspath(os.path.dirname(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
sys.path.insert(0, REPO)


def bench_reset_only(n, cfg):
    from OAuthMapper.OAuthSUT import OAuthSUT
    from core.config import OAuthConfig
    o = cfg.get('oauth', {})
    oc = OAuthConfig(base_url=o.get('base_url', 'http://127.0.0.1:8080'),
                     realm=o.get('realm', 'master'),
                     client_id=o.get('client_id', 'fuzz-client'),
                     client_secret=o.get('client_secret', 'x'),
                     redirect_uri=o.get('redirect_uri', 'http://127.0.0.1:7777/callback'),
                     username=o.get('user', 'u'), password=o.get('password', 'p'),
                     scope=o.get('scope', 'openid'),
                     target_type=cfg.get('target_type', 'keycloak'))
    sut = OAuthSUT(oc, target_type=cfg.get('target_type', 'keycloak'))
    sut.reset()
    t0 = time.time()
    for _ in range(n):
        sut.reset()
    dt = time.time() - t0
    return {'n': n, 'total_s': round(dt, 3), 'per_reset_ms': round(1000.0 * dt / n, 3)}


def bench_end_to_end(n, cfg):
    from OAuthMapper.OAuthSUT import OAuthSUT
    from core.config import OAuthConfig
    o = cfg.get('oauth', {})
    oc = OAuthConfig(base_url=o.get('base_url', 'http://127.0.0.1:8080'),
                     realm=o.get('realm', 'master'),
                     client_id=o.get('client_id', 'fuzz-client'),
                     client_secret=o.get('client_secret', 'x'),
                     redirect_uri=o.get('redirect_uri', 'http://127.0.0.1:7777/callback'),
                     username=o.get('user', 'u'), password=o.get('password', 'p'),
                     scope=o.get('scope', 'openid'),
                     target_type=cfg.get('target_type', 'keycloak'))
    sut = OAuthSUT(oc, target_type=cfg.get('target_type', 'keycloak'))
    times = []
    for _ in range(n):
        t0 = time.time()
        sut.reset()
        try:
            sut.step('Authorize')
        except Exception:
            pass
        times.append(time.time() - t0)
    return {'n': n, 'mean_seq_s': round(statistics.mean(times), 4),
            'median_seq_s': round(statistics.median(times), 4),
            'est_1000_seq_min': round(statistics.mean(times) * 1000 / 60.0, 2)}


def bench_container_restart(m, container, health_url, mgr_start_cmd=None):
    cycles = []
    for i in range(m):
        t0 = time.time()
        subprocess.run(['docker', 'start', container], capture_output=True)
        # wait for health
        import requests
        for _ in range(120):
            try:
                if requests.get(health_url, timeout=3, verify=False).status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(2)
        subprocess.run(['docker', 'stop', '-t', '20', container], capture_output=True,
                       timeout=180)
        cycles.append(round(time.time() - t0, 1))
    per = statistics.mean(cycles) if cycles else None
    return {'n_cycles': m, 'cycle_seconds': cycles,
            'mean_cycle_min': round(per / 60.0, 2) if per else None,
            'est_1000_seq_min': round(per * 1000 / 60.0, 1) if per else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', default=os.path.join(REPO, 'configs', 'oauth_keycloak.json'))
    ap.add_argument('--container', default='keycloak-fuzz-coverage')
    ap.add_argument('--health', default='http://127.0.0.1:8080/realms/master')
    ap.add_argument('--n-reset', type=int, default=1000)
    ap.add_argument('--n-seq', type=int, default=200)
    ap.add_argument('--n-restart', type=int, default=3)
    ap.add_argument('--out', default=os.path.join(HERE, 'results', 'bench_reset.json'))
    args = ap.parse_args()

    with open(args.config) as f:
        cfg = json.load(f)

    result = {'config': args.config, 'timestamp': time.time()}
    result['session_reset_only'] = bench_reset_only(args.n_reset, cfg)
    result['end_to_end_light'] = bench_end_to_end(args.n_seq, cfg)
    result['container_restart'] = bench_container_restart(
        args.n_restart, args.container, args.health)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w') as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
