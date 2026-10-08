#!/usr/bin/env python3
"""
SimpleLogin Protocol Mixin for OAuth Fuzzing Framework.

SimpleLogin is a privacy-focused email aliasing service with OAuth2/OIDC support.
Key SimpleLogin-specific behaviors:
  - Endpoints mounted under /oauth2/ prefix
  - Standard Flask-based form login via /auth/login
  - CSRF token protection on login form (csrf_token hidden input)
  - Redirect-based authorization code flow with PKCE
  - No introspection, revocation, or end_session endpoints
"""

import re
import json
import urllib.parse
from typing import Tuple, Optional, Dict

import requests


class SimpleLoginProtocolMixin:
    """SimpleLogin OAuth2/OIDC protocol mixin for fuzzing.

    Standalone mixin (does NOT inherit from OAuthProtocolBase).
    Mixed into OAuthProtocol via multiple inheritance.
    """

    # ── Endpoint configuration ──────────────────────────────────────

    def _configure_endpoints(self):
        base = self.config.base_url.rstrip('/')

        self.auth_endpoint = f"{base}/oauth2/authorize"
        self.token_endpoint = f"{base}/oauth2/token"
        self.userinfo_endpoint = f"{base}/oauth2/userinfo"

        # SimpleLogin does not expose these endpoints
        self.device_endpoint = None
        self.introspect_endpoint = None
        self.revoke_endpoint = None
        self.end_session_endpoint = None

        # Standard attribute aliases
        for attr, default in (
            ('device_authorize_endpoint', self.device_endpoint),
            ('registration_endpoint', None),
            ('par_endpoint', None),
            ('jwks_endpoint', None),
            ('discovery_url', None),
        ):
            if not hasattr(self, attr):
                setattr(self, attr, default)

        self._simplelogin_base = base

    # ── authorize ──────────────────────────────────────────────────

    def authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        """GET /oauth2/authorize to start the OAuth2 flow.

        SimpleLogin redirects unauthenticated users to a login page.
        We capture the redirect Location (login page URL) so the login
        method can authenticate via the standard Flask form.
        """
        self._ensure_state_pkce()

        params = {
            'response_type': kwargs.get('response_type', 'code'),
            'client_id': kwargs.get('client_id', self.config.client_id),
            'redirect_uri': kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope': kwargs.get('scope', self.config.scope),
            'state': kwargs.get('state', self.state),
            'nonce': kwargs.get('nonce', self.nonce),
        }
        if self.code_challenge:
            params['code_challenge'] = kwargs.get('code_challenge', self.code_challenge)
            params['code_challenge_method'] = kwargs.get('code_challenge_method', 'S256')

        params = {k: v for k, v in params.items() if v is not None}
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"

        try:
            resp = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
            self._track_request('GET', url, dict(self.session.headers))
            self._track_response(resp)

            # Store the authorize params for re-use after authentication
            self._simplelogin_auth_params = params

            if resp.status_code in (302, 303):
                location = resp.headers.get('Location', '')
                self.last_location = location
                self.login_form_url = location

                # Parse the login form URL for later use
                self._parse_flow_url(location)

                # If already authenticated, location may contain code=
                if 'code=' in location:
                    code = self._extract_auth_code(location)
                    if code:
                        self.auth_code = code

            elif resp.status_code == 200:
                # Already authenticated or form rendered inline
                self.login_form_url = url

            return 'authorize', resp
        except Exception as e:
            return 'authorize_error', self._synthetic_response(500, str(e))

    # ── login ──────────────────────────────────────────────────────

    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        """Authenticate via SimpleLogin's Flask form login.

        Flow:
          1. If login_form_url is the authorize page (200), extract the /auth/login?next= link
          2. GET the login page to obtain CSRF token
          3. POST to the login URL (with ?next= param) with credentials
          4. Follow redirect chain to extract auth code
        """
        login_url = getattr(self, 'login_form_url', None)
        if not login_url:
            return 'login_error', self._synthetic_response(
                400, 'No login form URL (run authorize() first)')

        username = kwargs.get('username', self.config.username)
        password = kwargs.get('password', self.config.password)
        base = self._simplelogin_base

        try:
            # Resolve URL
            if not login_url.startswith('http'):
                login_url = f"{base}{login_url}"

            # Step 1: GET the page. If it's the authorize page, extract the login link.
            r0 = self.session.get(login_url, allow_redirects=True,
                                  timeout=10, verify=False)
            self._track_response(r0)

            # Check if this is the authorize page (has login link, not a login form)
            if 'name="csrf_token"' not in r0.text:
                # This is the authorize page - extract the login link
                link_match = re.search(r'href="(/auth/login\?[^"]+)"', r0.text)
                if link_match:
                    login_url = f"{base}{link_match.group(1).replace('&amp;', '&')}"
                    r0 = self.session.get(login_url, allow_redirects=True,
                                          timeout=10, verify=False)
                    self._track_response(r0)

            # Step 2: Extract CSRF token from the login form HTML
            csrf_token = None
            html = r0.text
            csrf_match = re.search(
                r'name="csrf_token"[^>]+value="([^"]*)"',
                html)
            if not csrf_match:
                csrf_match = re.search(
                    r'value="([^"]*)"[^>]+name="csrf_token"',
                    html)
            if csrf_match:
                csrf_token = csrf_match.group(1)

            # Step 3: POST to the login URL (preserves ?next= parameter)
            form_data = {
                'email': username,
                'password': password,
            }
            if csrf_token:
                form_data['csrf_token'] = csrf_token

            r1 = self.session.post(
                login_url, data=form_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded',
                         'Referer': login_url},
                allow_redirects=False, timeout=10, verify=False)
            self._track_response(r1)

            # Step 4: Follow redirect chain to extract auth code
            location = r1.headers.get('Location', '')
            last_resp = r1

            for i in range(10):
                if last_resp.status_code not in (301, 302, 303, 307, 308):
                    break
                if not location:
                    break

                # Resolve relative URL
                if not location.startswith('http'):
                    location = f"{base}{location}"

                self.last_location = location

                # Check if this redirect contains the auth code
                if 'code=' in location:
                    code = self._extract_auth_code(location)
                    if code:
                        self.auth_code = code
                    break

                # Follow the redirect
                r_next = self.session.get(
                    location, allow_redirects=False,
                    timeout=10, verify=False)
                self._track_response(r_next)
                last_resp = r_next
                location = r_next.headers.get('Location', '')

            return 'login', last_resp
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

    # ── auth_code_redirect ─────────────────────────────────────────

    def auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Extract the authorization code.

        For SimpleLogin, the code is obtained during login() via the
        redirect chain after form POST. If already captured, return
        immediately. Otherwise, follow the redirect chain.
        """
        if self.auth_code:
            mock = requests.Response()
            mock.status_code = 302
            mock.headers = {'Location': self.last_location or self.config.redirect_uri}
            mock._content = b''
            self._track_response(mock)
            return 'auth_code_redirect', mock

        # Try following the last_location redirect chain
        target = getattr(self, 'last_location', None)
        if not target:
            return 'auth_code_redirect_error', self._synthetic_response(
                400, 'No redirect location available')

        base = self._simplelogin_base
        for _ in range(10):
            try:
                if not target.startswith('http'):
                    target = f"{base}{target}"

                resp = self.session.get(
                    target, allow_redirects=False,
                    timeout=10, verify=False)
                self._track_response(resp)
            except Exception as e:
                return 'redirect_error', self._synthetic_response(500, str(e))

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get('Location', '')
                if not location:
                    return 'auth_code_final', resp
                if not location.startswith('http'):
                    location = f"{base}{location}"
                self.last_location = location
                if 'code=' in location:
                    code = self._extract_auth_code(location)
                    if code:
                        self.auth_code = code
                    return 'auth_code_redirect', resp
                target = location
            else:
                resp_url = getattr(resp, 'url', '')
                if 'code=' in resp_url:
                    code = self._extract_auth_code(resp_url)
                    if code:
                        self.auth_code = code
                return 'auth_code_final', resp

        return 'redirect_exhausted', self._synthetic_response(
            400, 'redirect chain too deep, no auth code found')

    # ── SimpleLogin-specific attack methods ──────────────────────────

    def simplelogin_csrf_bypass(self, **kwargs) -> Tuple[str, requests.Response]:
        """POST to /auth/login without CSRF token to test if it is enforced."""
        base = self._simplelogin_base
        login_url = f"{base}/auth/login"

        form_data = {
            'email': kwargs.get('email', self.config.username),
            'password': kwargs.get('password', self.config.password),
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        try:
            resp = self.session.post(
                login_url, data=form_data, headers=headers,
                allow_redirects=False, timeout=10, verify=False)
            self._track_response(resp)
            return 'simplelogin_csrf_bypass', resp
        except Exception as e:
            return 'simplelogin_csrf_bypass_error', self._synthetic_response(500, str(e))

    def simplelogin_open_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test malicious redirect_uri values in the authorize endpoint.

        SimpleLogin should validate redirect_uri against registered URIs.
        This tests various bypass techniques.
        """
        self._ensure_state_pkce()

        malicious = kwargs.get('redirects', [
            'http://evil.com',
            '//evil.com',
            'https://evil.com/callback',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
        ])
        redirect_uri = malicious[0] if isinstance(malicious, list) else malicious

        params = {
            'response_type': 'code',
            'client_id': kwargs.get('client_id', self.config.client_id),
            'redirect_uri': redirect_uri,
            'scope': kwargs.get('scope', self.config.scope),
            'state': kwargs.get('state', self.state),
        }
        if self.code_challenge:
            params['code_challenge'] = self.code_challenge
            params['code_challenge_method'] = 'S256'

        params = {k: v for k, v in params.items() if v is not None}
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"

        try:
            resp = self.session.get(url, allow_redirects=False,
                                    timeout=10, verify=False)
            self._track_response(resp)
            return 'simplelogin_open_redirect', resp
        except Exception as e:
            return 'simplelogin_open_redirect_error', self._synthetic_response(500, str(e))

    def simplelogin_token_replay(self, **kwargs) -> Tuple[str, requests.Response]:
        """Reuse an access token to test if it remains valid after expected expiry."""
        if not self.access_token:
            return 'simplelogin_token_replay_error', self._synthetic_response(
                400, 'no access_token available')

        headers = {
            'Authorization': f'Bearer {kwargs.get("token", self.access_token)}',
            'Accept': 'application/json',
        }

        try:
            resp = self.session.get(self.userinfo_endpoint, headers=headers,
                                    timeout=10, verify=False)
            self._track_response(resp)
            return 'simplelogin_token_replay', resp
        except Exception as e:
            return 'simplelogin_token_replay_error', self._synthetic_response(500, str(e))

    def simplelogin_scope_manipulation(self, **kwargs) -> Tuple[str, requests.Response]:
        """Request unsupported or escalated scopes in the authorize endpoint.

        Tests if SimpleLogin properly validates requested scopes against
        what the client is allowed to request.
        """
        self._ensure_state_pkce()

        escalated = kwargs.get('scopes', [
            'openid email profile admin',
            'openid root',
            'openid offline_access admin',
        ])
        scope = escalated[0] if isinstance(escalated, list) else escalated

        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': scope,
            'state': self.state,
            'nonce': self.nonce,
        }
        if self.code_challenge:
            params['code_challenge'] = self.code_challenge
            params['code_challenge_method'] = 'S256'

        params = {k: v for k, v in params.items() if v is not None}
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"

        try:
            resp = self.session.get(url, allow_redirects=False,
                                    timeout=10, verify=False)
            self._track_response(resp)
            return 'simplelogin_scope_manipulation', resp
        except Exception as e:
            return 'simplelogin_scope_manipulation_error', self._synthetic_response(
                500, str(e))

    def simplelogin_client_impersonation(self, **kwargs) -> Tuple[str, requests.Response]:
        """Use a different client_id in the token exchange step.

        Obtains an auth code with one client, then tries to exchange it
        using a different client's credentials.
        """
        if not self.auth_code:
            return 'simplelogin_client_impersonation_error', self._synthetic_response(
                400, 'no auth_code available (complete authorize + login first)')

        evil_client_id = kwargs.get('evil_client_id', 'evil-impersonator-client')
        evil_client_secret = kwargs.get('evil_client_secret', 'evil-secret')

        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': evil_client_id,
            'client_secret': evil_client_secret,
        }
        if self.code_verifier:
            data['code_verifier'] = self.code_verifier

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'}

        try:
            resp = self.session.post(self.token_endpoint, data=data,
                                     headers=headers, timeout=10, verify=False)
            self._track_response(resp)
            return 'simplelogin_client_impersonation', resp
        except Exception as e:
            return 'simplelogin_client_impersonation_error', self._synthetic_response(
                500, str(e))

    # ── Internal helpers ────────────────────────────────────────────

    def _parse_flow_url(self, flow_url: str):
        """Store login form URL from the authorize redirect Location.

        Simpler than Authentik's flow executor URL parsing since
        SimpleLogin uses standard Flask form login.
        """
        base = self._simplelogin_base
        if not flow_url:
            self._simplelogin_login_url = None
            return

        # Resolve relative URL
        if not flow_url.startswith('http'):
            flow_url = f"{base}{flow_url}"

        self._simplelogin_login_url = flow_url

    def _synthetic_response(self, status: int, text: str) -> requests.Response:
        """Create a synthetic requests.Response for error cases."""
        r = requests.Response()
        r.status_code = status
        r._content = (text or '').encode('utf-8')
        return r
