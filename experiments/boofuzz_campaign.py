#!/usr/bin/env python3
"""Vanilla BooFuzz baseline campaign, adapted from the
OAuthLancer rq1 baseline with two changes:

  1. --port CLI: lanes with isolated target instances can point at any port.
  2. Raw-corpus logging: a custom IFuzzLogger captures every transmitted
     request (Target.send -> log_send) into corpus_raw/<n>.req — this is the
     post-hoc corpus-replay input, mirroring AFLNet's queue files.

BooFuzz remains vanilla (pip boofuzz 0.4.2 metadata; this install exposes the
sulley-lineage API: s_initialize/s_get global-request construction and
session.add_target/connect registration — the upstream-0.4.x `request=` kwarg
and Session.add do NOT exist here). No protocol state, no oracle, watchdog
restart. Coverage measured externally by coverage_sampler.py.
"""
import argparse
import json
import os
import sys
import time
import traceback

HERE = os.path.abspath(os.path.dirname(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))

from boofuzz import (Session, Target, TCPSocketConnection,  # noqa: E402
                     s_string, s_static, s_delim, s_initialize, s_get)
from boofuzz.ifuzz_logger import IFuzzLogger  # noqa: E402
from urllib.parse import urlparse  # noqa: E402

# The fork's Session ALWAYS attaches an internal sqlite FuzzLoggerDb that
# records every transmitted case to <cwd>/boofuzz-results/run-*.db — ~2-4GB
# per 6h campaign (the Sept-24 ENOSPC #3). Our corpus record is the
# RawCorpusLogger; neutralize the db logger entirely.
import boofuzz.fuzz_logger_db as _fldb  # noqa: E402


class _NoopDbLogger:
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, name):
        return lambda *a, **k: None


_fldb.FuzzLoggerDb = _NoopDbLogger

DEFAULT_PORTS = {'cxf_oauth': 8081, 'keycloak': 8080, 'authelia': 9091,
                 'ory_hydra': 4444, 'casdoor': 8000}

# sulley registers requests by name in a GLOBAL registry; the watchdog loop
# re-builds the session after each completed pass, so names must be unique
# per build_session call (else SullyRuntimeError: REQUESTS ALREADY EXISTS).
_REQ_SEQ = [0]


def _uname(base):
    _REQ_SEQ[0] += 1
    return f'{base}_{_REQ_SEQ[0]}'


class RawCorpusLogger(IFuzzLogger):
    """Minimal IFuzzLogger: dump sent requests to corpus_raw/<n>.req.

    Vanilla BooFuzz has no coverage feedback, so it transmits EVERY mutated
    case: a 6h campaign at ~700 req/s would write ~15M files (~8GB), which
    neither disk nor the post-hoc replay pass can absorb. sample_n keeps
    every Nth transmitted request (uniform systematic subsample — replay
    coverage is measured on this subsample)."""

    def __init__(self, out_dir, sample_n=200):
        self.dir = os.path.join(out_dir, 'corpus_raw')
        os.makedirs(self.dir, exist_ok=True)
        self.n = len(os.listdir(self.dir))
        self.total = 0
        self.sample_n = max(1, int(sample_n))

    def log_send(self, data):
        try:
            if isinstance(data, str):
                data = data.encode('utf-8', 'ignore')
            if not data:
                return
            self.total += 1
            if self.sample_n > 1 and (self.total % self.sample_n) != 1:
                return
            self.n += 1
            with open(os.path.join(self.dir, f'{self.n:06d}.req'), 'wb') as f:
                f.write(data)
        except Exception:
            pass

    # --- no-op remainder of the IFuzzLogger interface ---
    def open_test_case(self, test_case_id, name, index, *args, **kwargs): pass
    def open_test_step(self, description): pass
    def log_info(self, description): pass
    def log_check(self, description): pass
    def log_pass(self, description=""): pass
    def log_fail(self, description=""): pass
    def log_error(self, description=""): pass
    def log_recv(self, data): pass
    def close_test_case(self): pass
    def close_test(self): pass
    def open_session(self, description=None): pass
    def close_session(self): pass


def build_session(target, seeds, out_dir, host, port):
    eps = seeds['endpoints']
    session = Session(
        session_filename=os.path.join(out_dir, 'boofuzz_session'),
        web_port=None,  # default web UI thread would collide across lanes
        receive_data_after_each_request=True,
        check_data_received_each_request=True,
        sleep_time=0.0,
        restart_threshold=None,
        fuzz_loggers=[RawCorpusLogger(out_dir)],
    )
    session.add_target(Target(connection=TCPSocketConnection(host, port)))

    az = seeds['authorize']['path_vars']
    az_path = urlparse(eps['authorize']).path
    # --- authorize (GET with fuzzable params) ------------------------------
    az_name = _uname('authorize')
    s_initialize(az_name)
    s_static('GET ')
    s_static(az_path + '?')
    first = True
    for k, v in az.items():
        if not first:
            s_delim('&')
        s_static(f'{k}=')
        s_string(v, fuzzable=True, max_len=1024)
        first = False
    s_static(' HTTP/1.1\r\nHost: ')
    s_static(f'{host}:{port}')
    s_static('\r\nConnection: close\r\n\r\n')
    session.connect(s_get(az_name))

    # --- token (POST form with fuzzable values) ----------------------------
    tk = seeds['token']['form']
    tk_path = urlparse(eps['token']).path
    tk_name = _uname('token')
    s_initialize(tk_name)
    s_static('POST ' + tk_path + ' HTTP/1.1\r\nHost: ')
    s_static(f'{host}:{port}')
    s_static('\r\nContent-Type: application/x-www-form-urlencoded\r\n'
             'Connection: close\r\nContent-Length: 512\r\n\r\n')
    first = True
    for k, v in tk.items():
        if not first:
            s_delim('&')
        s_static(f'{k}=')
        s_string(v, fuzzable=True, max_len=1024)
        first = False
    s_static('\r\n')
    session.connect(s_get(tk_name))
    return session


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True,
                    choices=list(DEFAULT_PORTS.keys()))
    ap.add_argument('--duration-h', type=float, default=6.0)
    ap.add_argument('--port', type=int, default=None)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    port = args.port or DEFAULT_PORTS[args.target]
    seeds_path = os.path.join(HERE, 'boofuzz_seeds', f'{args.target}.json')
    seeds = json.load(open(seeds_path))
    os.makedirs(args.out, exist_ok=True)
    t0 = time.time()
    restarts = 0
    log = open(os.path.join(args.out, 'campaign.log'), 'a')
    log.write(f'[cfg] target={args.target} host={args.host}:{port} '
              f'duration={args.duration_h}h\n')
    log.flush()

    while time.time() - t0 < args.duration_h * 3600:
        try:
            session = build_session(args.target, seeds, args.out, args.host, port)
            session.fuzz()
            restarts += 1
            log.write(f'[{time.time()-t0:.0f}s] full pass done, restart {restarts}\n')
            log.flush()
        except KeyboardInterrupt:
            break
        except Exception:
            restarts += 1
            log.write(f'[{time.time()-t0:.0f}s] exception, restart {restarts}\n')
            log.write(traceback.format_exc() + '\n')
            log.flush()
            time.sleep(2)
    log.write(f'done: restarts={restarts} duration={(time.time()-t0)/3600:.2f}h\n')
    log.close()
    with open(os.path.join(args.out, 'DONE'), 'w') as f:
        json.dump({'restarts': restarts,
                   'duration_h': round((time.time() - t0) / 3600, 3)}, f)


if __name__ == '__main__':
    main()
