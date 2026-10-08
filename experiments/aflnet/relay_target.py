#!/usr/bin/env python3
"""AFLNet connector target (spike): forwards AFLNet-mutated requests to a
running OAuth server and relays the response.

AFLNet's fork-server model expects the TARGET to be the network server. For
dockerized Java/Go targets we instead present this thin TCP relay as the
target: AFLNet connects to it, sends mutated request bytes; the relay
forwards to the real server and streams the response back, so AFLNet's
response-code feedback (-Y) reflects the real server's verdicts.

Usage inside afl-fuzz:
  afl-fuzz -i seeds/ -o out/ -N tcp://127.0.0.1:<relay_port>/ -P http \
      -Y '[1-5][0-9][0-9]' -- python3 relay_target.py <upstream_host:port> <relay_port>
"""
import socket
import sys
import threading

UPSTREAM = ('127.0.0.1', 8081)   # real target
RELAY_PORT = 26000               # where AFLNet connects

HTTP_EOP = b'\r\n\r\n'


def relay(conn):
    try:
        data = b''
        while HTTP_EOP not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        if not data:
            conn.close()
            return
        # parse Content-Length for POST bodies
        head, _, body = data.partition(HTTP_EOP)
        clen = 0
        for line in head.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                try:
                    clen = int(line.split(b':', 1)[1].strip())
                except ValueError:
                    clen = 0
        while len(body) < clen:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk
        full = head + HTTP_EOP + body

        up = socket.create_connection(UPSTREAM, timeout=10)
        up.sendall(full)
        up.shutdown(socket.SHUT_WR)
        resp = b''
        while True:
            try:
                chunk = up.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
        up.close()
        if resp:
            conn.sendall(resp)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    global UPSTREAM, RELAY_PORT
    if len(sys.argv) >= 3:
        host, _, port = sys.argv[1].partition(':')
        UPSTREAM = (host or '127.0.0.1', int(port or 8081))
        RELAY_PORT = int(sys.argv[2])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', RELAY_PORT))
    srv.listen(64)
    sys.stderr.write(f'[relay] upstream={UPSTREAM} listen={RELAY_PORT}\n')
    sys.stderr.flush()
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=relay, args=(conn,), daemon=True).start()


if __name__ == '__main__':
    main()
