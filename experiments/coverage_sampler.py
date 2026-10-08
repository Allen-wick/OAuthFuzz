#!/usr/bin/env python3
"""External coverage sampler for baseline campaigns (RQ1).

BooFuzz/AFLNet runs have no built-in coverage sink; this standalone process
samples the target's coverage while they run:
  - Jacoco mode: every --dump-interval s, TCP dump (append, no reset);
    every --point-interval s, generate report + record {t_h, branch_pct}.
  - covdata mode (Go -cover builds): every --point-interval s, run
    `go tool covdata percent -i=<dir>` inside the container via a host
    GOCOVERDIR volume and record total statement coverage.

Usage:
  python3 coverage_sampler.py --mode jacoco --port 6300 --duration-h 24 \
      --out implements/results/rq1/boofuzz_cxf/coverage_series.jsonl
  python3 coverage_sampler.py --mode covdata --covdir <hostdir> --container <name> ...
"""
import argparse
import json
import os
import re
import subprocess
import time




def _inject_classpaths(jm, workdir):
    """Report generation needs the analyzed classes on the classpath; the bare
    JaCoCoManager has none (managers set them at deploy). Rebuild the same
    selection the target managers use:
      - cxf_lib: jars extracted under cxf_lib/extracted (+ WEB-INF/classes)
      - keycloak_lib: org.keycloak.keycloak-* jars of the running version
    """
    import glob as _glob
    wd = os.path.abspath(args_workdir_global[0]) if args_workdir_global else os.path.abspath(workdir)
    jars = []
    for p in _glob.glob(os.path.join(wd, '**', '*.jar'), recursive=True):
        # EXCLUDE the sanitize-time jar backups — duplicate FQNs abort the
        # report CLI ("Can't add different class with same name")
        if 'original_jars_backup' in p:
            continue
        b = os.path.basename(p)
        if 'extracted' in p and (b.startswith('cxf-rt-rs-security-') or False):
            jars.append(p)
    # WEB-INF/classes directory from the extracted war
    for p in _glob.glob(os.path.join(wd, 'cxf_lib', 'extracted', 'WEB-INF', 'classes')):
        if os.path.isdir(p):
            jars.append(p)
    kc = []
    for p in _glob.glob(os.path.join(wd, '**', 'org.keycloak.keycloak-*.jar'), recursive=True):
        b = os.path.basename(p)
        if 'original_jars_backup' in p:
            continue
        if any(ex in b for ex in ('sssd-federation', 'kerberos-federation',
                                  'themes', 'admin-ui', 'account-ui')):
            continue
        if '26.4.6' in b or not any(v in b for v in ('26.0.0', '26.4.6', '26.7.0')):
            kc.append(p)
    seen = set()
    alljars = [p for p in jars + kc if not (p in seen or seen.add(p))]
    if alljars:
        jm.set_classpaths(alljars)
        print(f'[sampler] classpaths injected: {len(alljars)}', flush=True)
    else:
        print('[sampler] WARNING: no classpaths found', flush=True)

def jacoco_point(jm, out_f, t0):
    try:
        jm.generate_report()
        xml = os.path.join(jm.work_dir, 'reports', 'coverage.xml')
        branch_pct = instr_pct = None
        if os.path.exists(xml):
            # report-level summary counters sit at the END of the XML (after
            # all package/class elements) — read the whole file, take the LAST
            # counter of each type
            with open(xml, encoding='utf-8', errors='ignore') as f:
                body = f.read()
            instr_all = re.findall(r'<counter type="INSTRUCTION" missed="(\d+)" covered="(\d+)"', body)
            if instr_all:
                miss, cov = map(int, instr_all[-1])
                instr_pct = 100.0 * cov / max(1, cov + miss)
            branch_all = re.findall(r'<counter type="BRANCH" missed="(\d+)" covered="(\d+)"', body)
            if branch_all:
                miss, cov = map(int, branch_all[-1])
                branch_pct = 100.0 * cov / max(1, cov + miss)
        rec = {'t_h': round((time.time() - t0) / 3600, 4),
               'branch_pct': round(branch_pct, 4) if branch_pct is not None else None,
               'instr_pct': round(instr_pct, 4) if instr_pct is not None else None}
        out_f.write(json.dumps(rec) + '\n')
        out_f.flush()
        print('[sampler]', rec, flush=True)
    except Exception as e:
        print('[sampler] point failed:', e, flush=True)


def covdata_point(covdir, out_f, t0):
    try:
        r = subprocess.run(['go', 'tool', 'covdata', 'func', '-i=' + covdir],
                           capture_output=True, text=True, timeout=120)
        total = None
        for line in r.stdout.splitlines():
            if re.match(r'\s*total\s+\(statements\)', line):
                m = re.search(r'([\d.]+)%\s*$', line.strip())
                if m:
                    total = float(m.group(1))
        rec = {'t_h': round((time.time() - t0) / 3600, 4), 'covdata_pct': total}
        out_f.write(json.dumps(rec) + '\n')
        out_f.flush()
        print('[sampler]', rec, flush=True)
    except Exception as e:
        print('[sampler] covdata point failed:', e, flush=True)


args_workdir_global = []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=['jacoco', 'covdata'], required=True)
    ap.add_argument('--port', type=int, default=6300)
    ap.add_argument('--jacoco-workdir', default='jacoco_tools')
    ap.add_argument('--covdir', default=None)
    ap.add_argument('--duration-h', type=float, default=24.0)
    ap.add_argument('--dump-interval', type=float, default=300)
    ap.add_argument('--point-interval', type=float, default=1800)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    args_workdir_global.append(args.jacoco_workdir)
    out_f = open(args.out, 'a')
    t0 = time.time()
    jm = None
    if args.mode == 'jacoco':
        import sys
        # this copy lives at CS_OAuthFuzz/experiments/ (2 levels shallower
        # than the OAuthLancer rq1_baselines original — repo root is 3 up)
        sys.path.insert(0, os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', '..', '..')))
        from core.coverage import JaCoCoManager
        jm = JaCoCoManager(work_dir=args.jacoco_workdir)
        _inject_classpaths(jm, args.jacoco_workdir)

    last_point = 0.0
    end = args.duration_h * 3600
    # Bounded-exec sampling: dump WITH --reset (deltas appended to the exec
    # file keep the union; without reset each dump re-appends the full
    # session state and the file grows to GBs over a 6h campaign)
    if args.mode == 'jacoco':
        jm.max_exec_mb = 400
    while time.time() - t0 < end:
        time.sleep(min(args.dump_interval, 30))
        now = time.time() - t0
        if args.mode == 'jacoco':
            try:
                jm.dump_coverage_reset(port=args.port)
            except Exception as e:
                print('[sampler] dump failed:', e, flush=True)
            if now - last_point >= args.point_interval:
                jacoco_point(jm, out_f, t0)
                last_point = now
        else:
            if now - last_point >= args.point_interval:
                covdata_point(args.covdir, out_f, t0)
                last_point = now
    # final point
    if args.mode == 'jacoco':
        try:
            jm.dump_coverage_reset(port=args.port)
        except Exception:
            pass
        jacoco_point(jm, out_f, t0)
    else:
        covdata_point(args.covdir, out_f, t0)
    out_f.close()
    print('[sampler] done')


if __name__ == '__main__':
    main()
