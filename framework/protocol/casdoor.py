#!/usr/bin/env python3
"""
Casdoor Protocol Mixin for OAuth Fuzzing Framework.

Casdoor is a Go-based IAM (Beego + XORM + Casbin) with OAuth2/OIDC support.
Endpoints follow the pattern: /api/login/oauth/<action>

Key Casdoor-specific flows:
  - Authorization: GET /api/login/oauth/authorize (redirects to login page)
  - Token exchange: POST /api/login/oauth/access_token
  - UserInfo: GET /api/userinfo
  - Introspection: POST /api/login/oauth/introspect
  - Discovery: /.well-known/openid-configuration
"""

import re
import html
import json
import urllib.parse
from typing import Tuple, Optional, Dict

import requests


class CasdoorProtocolMixin:
    """Casdoor OAuth2/OIDC protocol mixin for fuzzing."""

    # ── Endpoint configuration ──────────────────────────────────────

    def _configure_endpoints(self):
        base = self.config.base_url.rstrip('/')
        self.auth_endpoint = f"{base}/api/login/oauth/authorize"
        self.token_endpoint = f"{base}/api/login/oauth/access_token"
        self.userinfo_endpoint = f"{base}/api/userinfo"
        self.introspect_endpoint = f"{base}/api/login/oauth/introspect"
        self.revoke_endpoint = None  # Casdoor does not implement revocation
        self.jwks_endpoint = f"{base}/.well-known/jwks"
        self.discovery_url = f"{base}/.well-known/openid-configuration"
        self.end_session_endpoint = f"{base}/api/logout"

        # Casdoor-specific endpoints
        self._casdoor_login_page = f"{base}/api/login"
        self._casdoor_signup_url = f"{base}/api/signup"
        self._casdoor_auto_signin_url = f"{base}/api/auto-signin"

    # ── Standard OAuth2/ODIC authorize ──────────────────────────────

    def authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        """GET /api/login/oauth/authorize — start authorization code flow."""
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

        # Handle fuzzing overrides
        if 'redirect_uri' in kwargs:
            params['redirect_uri'] = kwargs['redirect_uri']
        if 'scope' in kwargs:
            params['scope'] = kwargs['scope']
        if 'state' in kwargs:
            params['state'] = kwargs['state']
        if 'prompt' in kwargs:
            params['prompt'] = kwargs['prompt']

        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        resp = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
        self._track_request('GET', url, dict(self.session.headers))
        self._track_response(resp)

        if resp.status_code in (302, 303):
            self.last_location = resp.headers.get('Location', '')
        return 'Redirect' if resp.status_code in (302, 303) else 'Success', resp

    # ── Login ───────────────────────────────────────────────────────

    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        """POST login — Casdoor uses /api/login with form data."""
        username = kwargs.get('username', self.config.username)
        password = kwargs.get('password', self.config.password)

        # Casdoor login endpoint accepts POST with application/x-www-form-urlencoded
        data = {
            'username': username,
            'password': password,
            'type': 'login',
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': self.last_location or self.auth_endpoint,
        }

        # Build URL from last redirect location (contains the login page with state)
        login_url = self.last_location if self.last_location and 'login' in self.last_location \
            else f"{self.config.base_url.rstrip('/')}/api/login"

        resp = self.session.post(login_url, data=data, headers=headers,
                                 allow_redirects=False, timeout=10, verify=False)
        self._track_request('POST', login_url, headers, data)
        self._track_response(resp)

        if resp.status_code in (302, 303):
            self.last_location = resp.headers.get('Location', '')
            # Extract auth code from redirect
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
        """Handle Casdoor consent page (if enabled)."""
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

    # ── Casdoor-specific attack methods ─────────────────────────────

    def casdoor_auto_signin_password_in_url(self, **kwargs) -> Tuple[str, requests.Response]:
        """C9 MEDIUM: Test AutoSigninFilter accepting passwords in GET query params."""
        username = kwargs.get('username', self.config.username)
        password = kwargs.get('password', self.config.password)
        base = self.config.base_url.rstrip('/')

        params = {'username': username, 'password': password}
        url = f"{base}/api/auto-signin?{urllib.parse.urlencode(params)}"
        resp = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
        self._track_request('GET', url, dict(self.session.headers))
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp

    def casdoor_session_cookie_flags(self, **kwargs) -> Tuple[str, requests.Response]:
        """C8 MEDIUM: Check session cookies for missing security flags."""
        base = self.config.base_url.rstrip('/')
        # Trigger any page that sets a session cookie
        url = f"{base}/api/get-account"
        resp = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
        self._track_request('GET', url, dict(self.session.headers))
        self._track_response(resp)
        return 'Success', resp

    def casdoor_userinfo_cors_open(self, **kwargs) -> Tuple[str, requests.Response]:
        """C17 INFO: Check if userinfo CORS is open to any origin."""
        headers = {
            'Origin': kwargs.get('origin', 'http://evil.com'),
            'Authorization': f"Bearer {self.access_token or 'invalid'}",
        }
        resp = self.session.get(self.userinfo_endpoint, headers=headers,
                                timeout=10, verify=False)
        self._track_request('GET', self.userinfo_endpoint, headers)
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp

    def casdoor_token_cors_origin_echo(self, **kwargs) -> Tuple[str, requests.Response]:
        """C17 INFO: Check if CORS echos origin with credentials on token endpoint."""
        headers = {
            'Origin': kwargs.get('origin', 'http://evil.com'),
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        data = {
            'grant_type': 'client_credentials',
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        resp = self.session.post(self.token_endpoint, data=data, headers=headers,
                                 timeout=10, verify=False)
        self._track_request('POST', self.token_endpoint, headers, data)
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp

    def casdoor_auth_code_replay(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test authorization code anti-replay protection (C13 race condition)."""
        if not self.auth_code:
            self.auth_code = kwargs.get('code')
        if not self.auth_code:
            return 'Status0', None

        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        resp = self.session.post(self.token_endpoint, data=data,
                                 timeout=10, verify=False)
        self._track_request('POST', self.token_endpoint,
                           {'Content-Type': 'application/x-www-form-urlencoded'}, data)
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp

    def casdoor_introspection_client_id_substitution(self, **kwargs) -> Tuple[str, requests.Response]:
        """C1 MEDIUM: Verify introspection replaces token's client_id with calling app's."""
        token = kwargs.get('token', self.access_token or 'test')
        data = {
            'token': token,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        resp = self.session.post(self.introspect_endpoint, data=data,
                                 timeout=10, verify=False)
        self._track_request('POST', self.introspect_endpoint,
                           {'Content-Type': 'application/x-www-form-urlencoded'}, data)
        self._track_response(resp)
        return 'Success' if resp.status_code == 200 else f'Status{resp.status_code}', resp

    def casdoor_pkce_not_enforced(self, **kwargs) -> Tuple[str, requests.Response]:
        """C2 LOW: Verify PKCE is not enforced for clients without code_challenge."""
        self._ensure_state_pkce()
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scope,
            'state': self.state,
        }
        # Deliberately omit code_challenge
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        resp = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
        self._track_request('GET', url, dict(self.session.headers))
        self._track_response(resp)

        if resp.status_code in (302, 303):
            self.last_location = resp.headers.get('Location', '')
        return 'Redirect' if resp.status_code in (302, 303) else 'Success', resp
