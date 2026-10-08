#!/usr/bin/env python3
"""
node-oidc-provider Protocol Mixin for OAuth Fuzzing Framework.

node-oidc-provider is an OpenID Certified Node.js OAuth 2.0 / OIDC provider
library by panva.  This mixin handles its protocol specifics:
  - Endpoints mounted under /oidc prefix (auth, token, me, introspection, revocation)
  - PKCE S256 enforced by default
  - Auto-approve interactions (server.js handles login + consent automatically)
  - Full OIDC: authorization code, refresh, client_credentials, device flow
  - Standard introspection and revocation endpoints
"""

import urllib.parse
import json
from typing import Tuple, Optional, Dict

import requests

from protocol.base import OAuthProtocolBase


class NodeOIDCProtocolMixin(OAuthProtocolBase):
    """node-oidc-provider protocol mixin for fuzzing.

    Standalone mixin inheriting from OAuthProtocolBase.
    Mixed into OAuthProtocol via multiple inheritance.
    """

    # ── Endpoint configuration ──────────────────────────────────────

    def _configure_endpoints(self):
        base = self.config.base_url.rstrip('/')
        # base already includes /oidc (e.g. http://127.0.0.1:3000/oidc)
        self.auth_endpoint = f"{base}/auth"
        self.token_endpoint = f"{base}/token"
        self.userinfo_endpoint = f"{base}/me"
        self.introspect_endpoint = f"{base}/token/introspection"
        self.revoke_endpoint = f"{base}/token/revocation"
        self.jwks_endpoint = f"{base}/jwks"
        self.device_authorize_endpoint = f"{base}/device/auth"

        # Standard attribute aliases
        for attr, default in (
            ('registration_endpoint', None),
            ('par_endpoint', None),
            ('end_session_endpoint', f"{base}/session/end"),
        ):
            if not hasattr(self, attr):
                setattr(self, attr, default)

        self._nodeoidc_base = base

    # ── authorize ──────────────────────────────────────────────────

    def authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        """GET /auth to start the OAuth2 authorization code flow.

        node-oidc-provider auto-approves interactions (login + consent
        handled by server.js), so the response is typically a 302 redirect
        directly to the callback URL with code= parameter.
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
            self._authorize_url = url
            self._authorize_response = resp

            location = resp.headers.get('Location', '')
            self.last_location = location

            # Track login form URL if redirected to interaction page
            if location and '/interaction/' in location:
                base_plain = self.config.base_url.rstrip('/').replace('/oidc', '')
                self.login_form_url = (
                    location if location.startswith('http')
                    else base_plain + location
                )

            # Direct approval: code in the redirect Location
            if location and 'code=' in location:
                code = self._extract_auth_code(location)
                if code:
                    self.auth_code = code

            return 'authorize', resp
        except Exception as e:
            return 'authorize_error', self._synthetic_response(500, str(e))

    # ── login ──────────────────────────────────────────────────────

    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        """Handle login step.

        With auto-approve interactions, the login is handled by the server
        automatically. This method follows the interaction redirect chain
        to complete the auto-approval and extract the auth code.
        """
        # If code already captured by authorize(), return success
        if self.auth_code:
            mock = requests.Response()
            mock.status_code = 302
            mock.headers['Location'] = self.last_location or ''
            mock._content = b''
            self._track_response(mock)
            return 'login', mock

        # Follow the redirect chain to trigger auto-approval
        target = getattr(self, 'last_location', None)
        if not target:
            return 'login_error', self._synthetic_response(
                400, 'No redirect location (run authorize() first)')

        base_plain = self._nodeoidc_base.replace('/oidc', '')
        try:
            for _ in range(8):
                if not target.startswith('http'):
                    target = f"{base_plain}{target}"

                resp = self.session.get(target, allow_redirects=False,
                                        timeout=10, verify=False)
                self._track_response(resp)

                location = resp.headers.get('Location', '')
                if not location:
                    return 'login', resp

                if not location.startswith('http'):
                    location = f"{base_plain}{location}"

                self.last_location = location

                # Check if redirect now contains the auth code
                if 'code=' in location:
                    code = self._extract_auth_code(location)
                    if code:
                        self.auth_code = code
                    return 'login', resp

                target = location

            return 'login_exhausted', self._synthetic_response(
                400, 'Redirect chain too deep, no auth code')
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

    # ── auth_code_redirect ─────────────────────────────────────────

    def auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Extract the authorization code from the redirect chain.

        node-oidc-provider typically redirects directly to the callback
        with code= after auto-approving the interaction. If code was
        already captured, return immediately.
        """
        if self.auth_code:
            mock = requests.Response()
            mock.status_code = 302
            mock.headers['Location'] = self.last_location or self.config.redirect_uri
            mock._content = b''
            self._track_response(mock)
            return 'auth_code_redirect', mock

        target = getattr(self, 'last_location', None)
        if not target:
            return 'auth_code_redirect_error', self._synthetic_response(
                400, 'No redirect location available')

        base_plain = self._nodeoidc_base.replace('/oidc', '')
        for _ in range(8):
            try:
                if not target.startswith('http'):
                    target = f"{base_plain}{target}"

                resp = self.session.get(target, allow_redirects=False,
                                        timeout=10, verify=False)
                self._track_response(resp)
            except Exception as e:
                return 'redirect_error', self._synthetic_response(500, str(e))

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get('Location', '')
                if not location:
                    return 'auth_code_final', resp
                if not location.startswith('http'):
                    location = f"{base_plain}{location}"
                self.last_location = location
                if 'code=' in location:
                    code = self._extract_auth_code(location)
                    if code:
                        self.auth_code = code
                    return 'auth_code_redirect', resp
                target = location
            else:
                return 'auth_code_final', resp

        return 'redirect_exhausted', self._synthetic_response(
            400, 'Redirect chain too deep, no auth code')

    # ── node-oidc-provider specific attack methods ───────────────────

    def nodeoidc_pkce_plain(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test if plain code_challenge_method is accepted (S256-only enforcement)."""
        self._ensure_state_pkce()

        params = {
            'response_type': 'code',
            'client_id': kwargs.get('client_id', self.config.client_id),
            'redirect_uri': kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope': kwargs.get('scope', self.config.scope),
            'state': kwargs.get('state', self.state),
            'code_challenge': kwargs.get('code_challenge', 'plaintext-challenge'),
            'code_challenge_method': 'plain',
        }
        params = {k: v for k, v in params.items() if v is not None}
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"

        try:
            resp = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
            self._track_request('GET', url, dict(self.session.headers))
            self._track_response(resp)
            return 'nodeoidc_pkce_plain', resp
        except Exception as e:
            return 'nodeoidc_pkce_plain_error', self._synthetic_response(500, str(e))

    def nodeoidc_code_replay(self, **kwargs) -> Tuple[str, requests.Response]:
        """Exchange the same auth code twice to test replay detection."""
        if not self.auth_code:
            return 'nodeoidc_code_replay_error', self._synthetic_response(
                400, 'No auth_code available')

        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        if self.code_verifier:
            data['code_verifier'] = self.code_verifier

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'}

        try:
            resp = self.session.post(self.token_endpoint, data=data,
                                     headers=headers, timeout=10, verify=False)
            self._track_request('POST', self.token_endpoint, headers, data)
            self._track_response(resp)
            return 'nodeoidc_code_replay', resp
        except Exception as e:
            return 'nodeoidc_code_replay_error', self._synthetic_response(500, str(e))

    def nodeoidc_invalid_code_verifier(self, **kwargs) -> Tuple[str, requests.Response]:
        """Exchange auth code with wrong code_verifier to test PKCE enforcement."""
        if not self.auth_code:
            return 'nodeoidc_invalid_verifier_error', self._synthetic_response(
                400, 'No auth_code available')

        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'code_verifier': 'wrong-verifier-value',
        }

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'}

        try:
            resp = self.session.post(self.token_endpoint, data=data,
                                     headers=headers, timeout=10, verify=False)
            self._track_request('POST', self.token_endpoint, headers, data)
            self._track_response(resp)
            return 'nodeoidc_invalid_verifier', resp
        except Exception as e:
            return 'nodeoidc_invalid_verifier_error', self._synthetic_response(500, str(e))

    def nodeoidc_introspection_cross_client(self, **kwargs) -> Tuple[str, requests.Response]:
        """Introspect a token using different client credentials."""
        if not self.access_token:
            return 'nodeoidc_introspect_cross_error', self._synthetic_response(
                400, 'No access_token available')

        evil_client_id = kwargs.get('evil_client_id', 'evil-attacker-client')
        evil_client_secret = kwargs.get('evil_client_secret', 'evil-secret')

        data = {
            'token': kwargs.get('token', self.access_token),
            'client_id': evil_client_id,
            'client_secret': evil_client_secret,
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'}

        try:
            resp = self.session.post(self.introspect_endpoint, data=data,
                                     headers=headers, timeout=10, verify=False)
            self._track_request('POST', self.introspect_endpoint, headers, data)
            self._track_response(resp)
            return 'nodeoidc_introspect_cross', resp
        except Exception as e:
            return 'nodeoidc_introspect_cross_error', self._synthetic_response(500, str(e))

    def nodeoidc_scope_escalation(self, **kwargs) -> Tuple[str, requests.Response]:
        """Request token with broader scopes than originally authorized."""
        self._ensure_state_pkce()

        escalated = kwargs.get('scopes', 'openid profile email admin root')
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': escalated,
            'state': self.state,
            'nonce': self.nonce,
        }
        if self.code_challenge:
            params['code_challenge'] = self.code_challenge
            params['code_challenge_method'] = 'S256'

        params = {k: v for k, v in params.items() if v is not None}
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"

        try:
            resp = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
            self._track_request('GET', url, dict(self.session.headers))
            self._track_response(resp)
            return 'nodeoidc_scope_escalation', resp
        except Exception as e:
            return 'nodeoidc_scope_escalation_error', self._synthetic_response(500, str(e))

    # ── Internal helpers ────────────────────────────────────────────

    def _extract_auth_code(self, url: str) -> Optional[str]:
        """Extract authorization code from a URL's query string."""
        try:
            q = urllib.parse.urlparse(url).query
            qp = urllib.parse.parse_qs(q)
            if 'code' in qp:
                return qp['code'][0]
        except Exception:
            pass
        return None

    def _synthetic_response(self, status: int, text: str) -> requests.Response:
        """Create a synthetic requests.Response for error cases."""
        r = requests.Response()
        r.status_code = status
        r._content = (text or '').encode('utf-8')
        return r
