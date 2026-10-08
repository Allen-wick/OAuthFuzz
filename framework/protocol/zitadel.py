#!/usr/bin/env python3
"""
Zitadel Protocol Mixin for OAuth Fuzzing Framework.

Zitadel is a Go-based IAM platform with OAuth2/OIDC support.
Endpoints follow the pattern: /oauth/v2/<action>

Key Zitadel characteristics:
  - OIDC certified provider
  - Supports PKCE, PAR, DPoP, JWT Profile, Token Exchange
  - Endpoints: /oauth/v2/authorize, /oauth/v2/token, /oidc/v1/userinfo
  - Admin API: /admin/v1, /management/v1, /auth/v1
  - gRPC & REST dual API surface
  - Well-known discovery at /.well-known/openid-configuration
"""

import re
import html
import json
import urllib.parse
from typing import Tuple, Optional, Dict

import requests


class ZitadelProtocolMixin:
    """Zitadel OAuth2/OIDC protocol mixin for fuzzing."""

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
                                           f"{base}/oauth/v2/authorize")
        self.token_endpoint = discovered.get('token_endpoint',
                                            f"{base}/oauth/v2/token")
        self.userinfo_endpoint = discovered.get('userinfo_endpoint',
                                                f"{base}/oidc/v1/userinfo")
        self.introspect_endpoint = discovered.get('introspection_endpoint',
                                                  f"{base}/oauth/v2/introspect")
        self.revoke_endpoint = discovered.get('revocation_endpoint',
                                              f"{base}/oauth/v2/revoke")
        self.jwks_endpoint = discovered.get('jwks_uri',
                                           f"{base}/oauth/v2/keys")
        self.end_session_endpoint = discovered.get('end_session_endpoint',
                                                   f"{base}/oidc/v1/end_session")
        self.par_endpoint = discovered.get('pushed_authorization_request_endpoint')
        self.discovery_url = f"{base}/.well-known/openid-configuration"

        # Zitadel-specific endpoints
        self._zitadel_login_url = f"{base}/ui/login"
        self._zitadel_api_base = f"{base}/management/v1"
        self._zitadel_admin_api = f"{base}/admin/v1"
        self._zitadel_auth_api = f"{base}/auth/v1"
        self._zitadel_system_api = f"{base}/system/v1"

    # ── Standard OAuth2/OIDC authorize ──────────────────────────────

    def authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        """GET /oauth/v2/authorize — start authorization code flow."""
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
                  'acr_values', 'login_hint', 'ui_locales', 'organization'):
            if k in kwargs:
                params[k] = kwargs[k]

        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        resp = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
        self._track_request('GET', url, dict(self.session.headers))
        self._track_response(resp)

        if resp.status_code in (302, 303):
            self.last_location = resp.headers.get('Location', '')
        return 'Redirect' if resp.status_code in (302, 303) else 'Success', resp

    # ── Login ───────────────────────────────────────────────────────

    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        """POST to Zitadel login UI — handles login page form submission."""
        username = kwargs.get('username', self.config.username)
        password = kwargs.get('password', self.config.password)

        # Zitadel login uses /ui/login with loginname and password
        login_url = self.last_location if self.last_location and 'login' in self.last_location \
            else f"{self.config.base_url.rstrip('/')}/ui/login"

        data = {
            'loginName': username,
            'password': password,
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': login_url,
        }

        resp = self.session.post(login_url, data=data, headers=headers,
                                 allow_redirects=False, timeout=10, verify=False)
        self._track_request('POST', login_url, headers, data)
        self._track_response(resp)

        if resp.status_code in (302, 303):
            self.last_location = resp.headers.get('Location', '')
            code = self._extract_auth_code(self.last_location)
            if code:
                self.auth_code = code
        return 'Redirect' if resp.status_code in (302, 303) else 'Success', resp

    # ── Auth code redirect ──────────────────────────────────────────

    def auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Follow redirect after login to extract authorization code."""
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
        """Handle Zitadel consent page."""
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

    # ── Zitadel-specific attack methods ─────────────────────────────

    def zitadel_api_probe(self, **kwargs) -> Tuple[str, requests.Response]:
        """Probe Zitadel API endpoints for unauthorized access."""
        endpoints = kwargs.get('endpoints', [
            '/management/v1/orgs/me',
            '/admin/v1/orgs',
            '/auth/v1/users/me',
            '/system/v1/instances',
        ])
        endpoint = kwargs.get('endpoint', endpoints[0])
        url = f"{self.config.base_url.rstrip('/')}{endpoint}"

        headers = {'Content-Type': 'application/json'}
        if self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'

        resp = self.session.get(url, headers=headers, timeout=10, verify=False)
        self._track_request('GET', url, headers)
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp

    def zitadel_mfa_bypass(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test MFA bypass — C15/C16: MFA endpoints without authentication."""
        base = self.config.base_url.rstrip('/')

        # Try MFA-related endpoints without proper auth
        endpoints = [
            f"{base}/auth/v1/users/me/mfas",
            f"{base}/management/v1/users/me/mfas",
        ]
        url = kwargs.get('url', endpoints[0])
        resp = self.session.get(url, timeout=10, verify=False)
        self._track_request('GET', url, dict(self.session.headers))
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp

    def zitadel_org_context_confusion(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test organization context confusion — multi-tenant isolation."""
        org_id = kwargs.get('org_id', 'attacker-org-id')

        # Try accessing resources in a different organization context
        headers = {
            'Content-Type': 'application/json',
            'x-zitadel-orgid': org_id,
        }
        url = f"{self.config.base_url.rstrip('/')}/management/v1/orgs/me"
        resp = self.session.get(url, headers=headers, timeout=10, verify=False)
        self._track_request('GET', url, headers)
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp

    def zitadel_token_exchange_impersonation(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test token exchange impersonation — audience binding enforcement."""
        data = {
            'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'subject_token': kwargs.get('subject_token', self.access_token or 'invalid'),
            'subject_token_type': 'urn:ietf:params:oauth:token-type:access_token',
            'scope': kwargs.get('scope', self.config.scope),
            'audience': kwargs.get('audience', 'different-client-id'),
        }
        resp = self.session.post(self.token_endpoint, data=data,
                                 timeout=10, verify=False)
        self._track_request('POST', self.token_endpoint,
                           {'Content-Type': 'application/x-www-form-urlencoded'}, data)
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp
