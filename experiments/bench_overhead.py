#!/usr/bin/env python3
"""RQ4 instrumentation-overhead benchmark (replaces the unbacked 5.2%).

Fixed request workload (GET /realms/master + POST token with bad creds)
against the SAME server binary with and without coverage instrumentation:

  - Java: plain `docker run quay.io/keycloak/keycloak start-dev` (no agent)
           vs the manager-started instance (JaCoCo tcpserver agent).
  - Go  : plain authelia image vs authelia-cover (-cover build).

N >= 2000 requests per side after warmup; report mean/median/p95 latency and
the relative overhead. Writes results/bench_overhead.json.
"""
import argparse
import json
import os
import statistics
import subprocess
import time

import requests
import urllib3

urllib3.disable_warnings()

HERE = os.path.abspath(os.path.dirname(__file__))


def workload(base, n, token_path='/realms/master/protocol/openid-connect/token',
             verify=False):
    """Mixed workload: 50% realm probe, 50% bad-credential token POST."""
    lat = []
    s = requests.Session()
    s.verify = verify
    for i in range(n):
        t0 = time.perf_counter()
        try:
            if i % 2 == 0:
                s.get(base + '/realms/master', timeout=10)
            else:
                s.post(base + token_path,
                       data={'grant_type': 'password', 'client_id': 'bench',
                             'username': 'x', 'password': 'x'}, timeout=10)
        except Exception:
            pass
        lat.append((time.perf_counter() - t0) * 1000.0)
    lat.sort()
    return {
        'n': n,
        'mean_ms': round(statistics.mean(lat), 2),
        'median_ms': round(statistics.median(lat), 2),
        'p95_ms': round(lat[int(0.95 * len(lat))], 2),
    }


def start_plain_keycloak(name, port):
    subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
    subprocess.run(['docker', 'run', '--rm', '-d', '--name', name,
                    '-p', f'{port}:8080',
                    '-e', 'KC_BOOTSTRAP_ADMIN_USERNAME=admin',
                    '-e', 'KC_BOOTSTRAP_ADMIN_PASSWORD=admin',
                    'quay.io/keycloak/keycloak:26.7.4', 'start-dev'],
                   capture_output=True)
    for _ in range(120):
        try:
            if requests.get(f'http://127.0.0.1:{port}/realms/master',
                            timeout=3).status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--instrumented-url', required=True,
                    help='URL of the agent-instrumented instance (already running)')
    ap.add_argument('--n', type=int, default=2000)
    ap.add_argument('--plain-port', type=int, default=38090)
    ap.add_argument('--plain-container', default='kc-bench-plain')
    ap.add_argument('--out', default=os.path.join(HERE, 'results', 'bench_overhead.json'))
    args = ap.parse_args()

    print('[bench] plain (uninstrumented) instance...')
    if not start_plain_keycloak(args.plain_container, args.plain_port):
        raise SystemExit('plain keycloak failed to start')
    workload(f'http://127.0.0.1:{args.plain_port}', 500)  # warmup (cold JVM needs hundreds for JIT)
    plain = workload(f'http://127.0.0.1:{args.plain_port}', args.n)

    print('[bench] instrumented instance...')
    workload(args.instrumented_url, 500)  # warmup
    inst = workload(args.instrumented_url, args.n)

    subprocess.run(['docker', 'rm', '-f', args.plain_container], capture_output=True)

    overhead = {
        'mean_rel_pct': round(100.0 * (inst['mean_ms'] / plain['mean_ms'] - 1.0), 2),
        'median_rel_pct': round(100.0 * (inst['median_ms'] / plain['median_ms'] - 1.0), 2),
    }
    result = {'n': args.n, 'plain': plain, 'instrumented': inst,
              'overhead': overhead, 'timestamp': time.time()}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, 'w') as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
