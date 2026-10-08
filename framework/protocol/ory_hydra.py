#!/usr/bin/env python3
"""
Ory Hydra Protocol Mixin for OAuth Fuzzing Framework.

Ory Hydra is a Go-based OAuth2/OIDC provider (certified).
Endpoints follow the pattern: /oauth2/<action>

Key Ory Hydra characteristics:
  - Pure OAuth2/OIDC provider (no user management — delegates to external IDP)
  - Login flow: /oauth2/auth?login_verifier=<verifier> -> /login -> /consent
  - Admin API: /admin/oauth2/auth/requests/login, /admin/oauth2/auth/requests/consent
  - Supports PKCE, PAR, DPoP, JWT access tokens
  - Well-known discovery at /.well-known/openid-configuration
"""

import re
import html
import json
import urllib.parse
from typing import Tuple, Optional, Dict

import requests


class OryHydraProtocolMixin:
    """Ory Hydra OAuth2/OIDC protocol mixin for fuzzing."""

    # ── Endpoint configuration ──────────────────────────────────────

    def _configure_endpoints(self):
        base = self.config.base_url.rstrip('/')

        # Try OIDC discovery
        discovered = {}
        try:
            discovery_url = f"{base}/.well-known/openid-configuration"
            r = requests.get(discovery_url, timeout=5,
                            headers={'Accept': 'application/json'},
                            verify=False)
            if r.status_code == 200:
                discovered = r.json()
        except Exception:
            pass

        self.auth_endpoint = discovered.get('authorization_endpoint',
                                           f"{base}/oauth2/auth")
        self.token_endpoint = discovered.get('token_endpoint',
                                            f"{base}/oauth2/token")
        self.userinfo_endpoint = discovered.get('userinfo_endpoint',
                                                f"{base}/userinfo")
        self.introspect_endpoint = discovered.get('introspection_endpoint',
                                                  f"{base}/admin/oauth2/introspect")
        self.revoke_endpoint = discovered.get('revocation_endpoint',
                                              f"{base}/oauth2/revoke")
        self.jwks_endpoint = discovered.get('jwks_uri',
                                           f"{base}/.well-known/jwks.json")
        self.end_session_endpoint = discovered.get('end_session_endpoint',
                                                   f"{base}/oauth2/sessions/logout")
        self.par_endpoint = discovered.get('pushed_authorization_request_endpoint',
                                          f"{base}/oauth2/par")
        self.discovery_url = f"{base}/.well-known/openid-configuration"

        # Ory Hydra-specific endpoints (admin API)
        self._hydra_admin_url = f"{base}/admin"
        self._hydra_login_url = f"{base}/admin/oauth2/auth/requests/login"
        self._hydra_consent_url = f"{base}/admin/oauth2/auth/requests/consent"
        self._hydra_accept_login_url = f"{base}/admin/oauth2/auth/requests/login/accept"
        self._hydra_accept_consent_url = f"{base}/admin/oauth2/auth/requests/consent/accept"

    # ── Standard OAuth2/OIDC authorize ──────────────────────────────

    def authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        """GET /oauth2/auth — start authorization code flow."""
        self._ensure_state_pkce()
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scope,
            'state': self.state,
            'nonce': self.nonce,
        }
        code_challenge_method = kwargs.get('code_challenge_method', 'S256')
        code_challenge = kwargs.get('code_challenge')
        if code_challenge:
            params['code_challenge'] = code_challenge
            params['code_challenge_method'] = code_challenge_method

        for k in ('redirect_uri', 'scope', 'state', 'prompt', 'max_age',
                  'acr_values', 'login_hint', 'ui_locales'):
            if k in kwargs:
                params[k] = kwargs[k]

        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        resp = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
        self._track_request('GET', url, dict(self.session.headers))
        self._track_response(resp)

        if resp.status_code in (302, 303):
            self.last_location = resp.headers.get('Location', '')
        return 'Redirect' if resp.status_code in (302, 303) else 'Success', resp

    # ── Login (via Ory Hydra admin API accept-login) ────────────────

    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        """POST accept login — Ory Hydra delegates login to external IDP.
        This method simulates the login acceptance via admin API."""
        username = kwargs.get('username', self.config.username)
        subject = kwargs.get('subject', username)

        if 'login_challenge' not in kwargs and self.last_location:
            parsed = urllib.parse.urlparse(self.last_location)
            qs = urllib.parse.parse_qs(parsed.query)
            login_challenge = qs.get('login_challenge', [None])[0]
            if not login_challenge:
                login_challenge = qs.get('login_verifier', [None])[0]
        else:
            login_challenge = kwargs.get('login_challenge')

        if not login_challenge:
            # Without a login challenge, this is a no-op (we can't perform login)
            return 'Skipped', None

        data = {
            'subject': subject,
            'remember': kwargs.get('remember', True),
            'remember_for': kwargs.get('remember_for', 3600),
        }
        headers = {'Content-Type': 'application/json'}
        url = f"{self._hydra_accept_login_url}?login_challenge={login_challenge}"

        resp = self.session.put(url, json=data, headers=headers,
                                allow_redirects=False, timeout=10, verify=False)
        self._track_request('PUT', url, headers, data)
        self._track_response(resp)

        if resp.status_code == 200:
            body = resp.json()
            redirect_to = body.get('redirect_to', '')
            if redirect_to:
                self.last_location = redirect_to
        return 'Redirect' if resp.status_code in (302, 303) else 'Success', resp

    # ── Auth code redirect ──────────────────────────────────────────

    def auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Follow redirect to extract authorization code."""
        target = self.last_location or self.auth_endpoint
        resp = self.session.get(target, allow_redirects=False, timeout=10, verify=False)
        self._track_request('GET', target, dict(self.session.headers))
        self._track_response(resp)

        if resp.status_code in (302, 303):
            location = resp.headers.get('Location', '')
            self.last_location = location
            code = self._extract_auth_code(location)
            if code:
                self.auth_code = code
        return 'Redirect' if resp.status_code in (302, 303) else 'Success', resp

    # ── Consent ─────────────────────────────────────────────────────

    def consent(self, **kwargs) -> Tuple[str, requests.Response]:
        """Handle Ory Hydra consent via admin API."""
        if 'consent_challenge' not in kwargs and self.last_location:
            parsed = urllib.parse.urlparse(self.last_location)
            qs = urllib.parse.parse_qs(parsed.query)
            consent_challenge = qs.get('consent_challenge', [None])[0]
        else:
            consent_challenge = kwargs.get('consent_challenge')

        if not consent_challenge:
            return 'Skipped', None

        data = {
            'grant_scope': kwargs.get('grant_scope', [self.config.scope]),
            'remember': kwargs.get('remember', True),
            'remember_for': kwargs.get('remember_for', 3600),
            'session': {
                'id_token': kwargs.get('id_token_claims', {}),
                'access_token': kwargs.get('access_token_claims', {}),
            },
        }
        headers = {'Content-Type': 'application/json'}
        url = f"{self._hydra_accept_consent_url}?consent_challenge={consent_challenge}"

        resp = self.session.put(url, json=data, headers=headers,
                                allow_redirects=False, timeout=10, verify=False)
        self._track_request('PUT', url, headers, data)
        self._track_response(resp)

        if resp.status_code == 200:
            body = resp.json()
            redirect_to = body.get('redirect_to', '')
            if redirect_to:
                self.last_location = redirect_to
        return 'Redirect' if resp.status_code in (302, 303) else 'Success', resp

    # ── Ory Hydra-specific attack methods ───────────────────────────

    def hydra_admin_api_probe(self, **kwargs) -> Tuple[str, requests.Response]:
        """Probe Ory Hydra admin API for unauthorized access."""
        endpoints = kwargs.get('endpoints', [
            '/admin/clients',
            '/admin/oauth2/auth/requests/login',
            '/admin/oauth2/auth/requests/consent',
            '/admin/keys',
        ])
        endpoint = kwargs.get('endpoint', endpoints[0])
        url = f"{self.config.base_url.rstrip('/')}{endpoint}"
        resp = self.session.get(url, timeout=10, verify=False)
        self._track_request('GET', url, dict(self.session.headers))
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp

    def hydra_client_creation_api(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test dynamic client registration / creation API."""
        data = {
            'client_name': kwargs.get('client_name', 'fuzz-dynamic-client'),
            'grant_types': kwargs.get('grant_types', ['authorization_code', 'refresh_token']),
            'redirect_uris': kwargs.get('redirect_uris', [self.config.redirect_uri]),
            'scope': kwargs.get('scope', self.config.scope),
            'token_endpoint_auth_method': kwargs.get('auth_method', 'client_secret_basic'),
        }
        headers = {'Content-Type': 'application/json'}
        url = f"{self.config.base_url.rstrip('/')}/admin/clients"
        resp = self.session.post(url, json=data, headers=headers,
                                 timeout=10, verify=False)
        self._track_request('POST', url, headers, data)
        self._track_response(resp)
        return 'Created' if resp.status_code == 201 else f'Status{resp.status_code}', resp

    def hydra_par_flood(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test PAR endpoint with oversized request bodies."""
        data = {
            'client_id': self.config.client_id,
            'response_type': 'code',
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scope,
            'state': self.state or 'par-test',
            'custom_claim': kwargs.get('payload', 'A' * 8192),
        }
        resp = self.session.post(self.par_endpoint, data=data,
                                 timeout=10, verify=False)
        self._track_request('POST', self.par_endpoint,
                           {'Content-Type': 'application/x-www-form-urlencoded'}, data)
        self._track_response(resp)
        return 'Success' if resp.status_code in (200, 201) else f'Status{resp.status_code}', resp
