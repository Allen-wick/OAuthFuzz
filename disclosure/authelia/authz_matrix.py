#!/usr/bin/env python3
"""
A2/A3/A4 — authz access-control engine matrix probes (anonymous forward-auth).

Decision codes:  200 Authorized(bypass) | 403 Forbidden(deny) | 401 Unauthorized(needs auth)
                 400 cookie-domain guard reject | 302 redirect-to-login (HTML accept)

A2 path-normalization (host 127.0.0.1): does Authelia's path.Clean(decoded) correctly
   resolve traversal so a deny rule catches /public/..%2fprivate ?
A3 wildcard-suffix (host under example.test): *.test rule matching, case sensitivity.
A4 resource-regex anchoring (host 127.0.0.1): does unanchored ^/sec over-match /section ?
"""
import requests, lib


def fa(host, uri="/", method="GET"):
    h = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": host,
         "X-Forwarded-URI": uri, "X-Forwarded-Method": method,
         "Accept": "application/json"}
    try:
        r = requests.get(f"{lib.BASE}/api/authz/forward-auth", headers=h,
                         verify=False, allow_redirects=False, timeout=8)
        return r.status_code
    except Exception as e:
        return f"ERR:{e}"


def label(code):
    return {200: "Authorized(bypass)", 403: "Forbidden(deny)",
            401: "Unauthorized(need-auth)"}.get(code, f"HTTP {code}")


def main():
    print("== A2: path normalization (host 127.0.0.1) ==")
    for uri in ["/public/index.html", "/private/secret.txt",
                "/public/..%2fprivate/secret.txt", "/public/../private/secret.txt",
                "/public/%2e%2e/private/secret.txt", "/public/..%2F..%2Fprivate/x"]:
        c = fa("127.0.0.1", uri)
        print(f"  {uri:42s} -> {c} {label(c)}")

    print("\n== A4: resource-regex anchoring (host 127.0.0.1, rule '^/sec' deny) ==")
    for uri in ["/sec", "/sec/", "/section", "/secretary", "/second/level"]:
        c = fa("127.0.0.1", uri)
        print(f"  {uri:18s} -> {c} {label(c)}   (note: /section,/secretary over-match ^/sec)")

    print("\n== A3: wildcard-suffix (rule '*.test' bypass; 'secure.test' deny) ==")
    for host in ["foo.example.test", "a.b.example.test", "Foo.Example.TEST",
                 "secure.test", "example.test"]:
        c = fa(host, "/")
        print(f"  host={host:22s} -> {c} {label(c)}")

    print("\n=== INTERPRETATION ===")
    print("A2: /public/..%2fprivate and /public/../private should hit the deny rule (403)")
    print("    if Authelia's path.Clean(decoded) resolves traversal (correct/secure).")
    print("A4: ^/sec unanchored over-matches /section, /secretary -> deny. Operator-misconfig class.")
    print("A3: *.test matches legit subdomains (200); case-variant fails closed (not bypass).")

if __name__ == "__main__":
    main()
