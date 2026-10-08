#!/usr/bin/env python3
"""One-shot relay variant for AFLNet per-exec model (dumb/-n mode).

Serves exactly ONE connection then exits: AFLNet (fuzzer side) connects to
RELAY_PORT, sends the mutated request; we forward to the real server, relay
the response, and exit — giving AFL a clean per-exec lifecycle without
fork-server instrumentation.

  afl-fuzz -i seeds -o out -n -N tcp://127.0.0.1:26000/ -P http \
      -Y '[1-5][0-9][0-9]' -- python3 relay_oneshot.py <up_host:up_port> <port>
"""
import socket
import sys

HTTP_EOP = b'\r\n\r\n'


def main():
    up_host, up_port = '127.0.0.1', 8081
    port = 26000
    if len(sys.argv) >= 3:
        h, _, p = sys.argv[1].partition(':')
        up_host, up_port = h or '127.0.0.1', int(p or 8081)
        port = int(sys.argv[2])

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('127.0.0.1', port))
    srv.listen(1)
    srv.settimeout(30)

    conn, _ = srv.accept()
    conn.settimeout(10)
    try:
        data = b''
        while HTTP_EOP not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        if data:
            head, _, body = data.partition(HTTP_EOP)
            clen = 0
            for line in head.split(b'\r\n'):
                if line.lower().startswith(b'content-length:'):
                    try:
                        clen = int(line.split(b':', 1)[1].strip())
                    except ValueError:
                        pass
            while len(body) < clen:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body += chunk
            up = socket.create_connection((up_host, up_port), timeout=10)
            up.sendall(head + HTTP_EOP + body)
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
            srv.close()
        except Exception:
            pass


if __name__ == '__main__':
    main()
