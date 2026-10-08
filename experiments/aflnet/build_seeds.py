#!/usr/bin/env python3
"""Per-target AFLNet raw-request seeds (fairness fix).

The prior campaign (OAuthLancer rq1 v1) accidentally fuzzed every lane with
CXF-shaped seeds (aflnet_campaign.sh defaulted SEEDS=seeds_cxf). This script
builds target-correct seeds: identical STRUCTURE (one GET authorize + one
POST token + introspection probes), endpoint paths/credentials taken from
each target's own config. Written into experiments/aflnet/seeds_<target>/.

Usage: python3 build_seeds.py [--targets cxf_oauth,keycloak,authelia]
"""
import argparse
import json
import os
from urllib.parse import urlparse, quote

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..', '..'))

CONFIGS = {
    'cxf_oauth': os.path.join(REPO, 'configs', 'oauth_cxf.json'),
    'keycloak': os.path.join(REPO, 'configs', 'oauth_keycloak.json'),
    'authelia': os.path.join(REPO, 'configs', 'oauth_authelia.json'),
}


def endpoint_paths(target, oauth):
    """Authorize/token paths per target (relay rewrites Host, not paths)."""
    base = urlparse(oauth.get('base_url', 'http://127.0.0.1:8080'))
    if target == 'cxf_oauth':
        return '/services/oauth2/authorize', '/services/oauth2/token', \
            '/services/oauth2/introspect'
    if target == 'keycloak':
        realm = oauth.get('realm', 'master')
        p = f'/realms/{realm}/protocol/openid-connect'
        return f'{p}/auth', f'{p}/token', f'{p}/token/introspect'
    if target == 'authelia':
        return '/api/oidc/authorization', '/api/oidc/token', \
            '/api/oidc/introspection'
    raise SystemExit(f'no seed recipe for target {target}')


def build(target):
    with open(CONFIGS[target]) as f:
        oauth = json.load(f).get('oauth', {})
    az, tk, intro = endpoint_paths(target, oauth)
    cid = oauth.get('client_id', 'fuzz-client')
    sec = oauth.get('client_secret', 'fuzz-client-secret')
    ruri = oauth.get('redirect_uri', 'http://127.0.0.1:7777/callback')
    scope = quote(oauth.get('scope', 'openid'))
    host_hdr = '127.0.0.1:26000'  # AFLNet speaks to the relay address

    seeds = {
        '01_authorize.req': (
            f"GET {az}?response_type=code&client_id={cid}"
            f"&redirect_uri={quote(ruri, safe='')}&scope={scope} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\nConnection: close\r\n\r\n"
        ),
        '02_token.req': (
            f"POST {tk} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: close\r\nContent-Length: 119\r\n\r\n"
            f"grant_type=authorization_code&code=abc123&client_id={cid}"
            f"&client_secret={sec}&redirect_uri={quote(ruri, safe='')}"
        ),
        '03_introspect.req': (
            f"POST {intro} HTTP/1.1\r\n"
            f"Host: {host_hdr}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Connection: close\r\nContent-Length: 45\r\n\r\n"
            f"token=abc123&client_id={cid}&client_secret={sec}"
        ),
    }
    out = os.path.join(HERE, f'seeds_{target}')
    os.makedirs(out, exist_ok=True)
    for name, content in seeds.items():
        with open(os.path.join(out, name), 'w') as f:
            f.write(content)
        print(f'seed {name}: {len(content)} bytes')
    print(f'{target} seeds -> {out}')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--targets', default='cxf_oauth,keycloak,authelia')
    for t in ap.parse_args().targets.split(','):
        build(t)
