#!/usr/bin/env python3
"""
Authentik Protocol Mixin for OAuth Fuzzing Framework.

Authentik is a Python/Django-based IAM provider with OAuth2/OIDC support.
Key Authentik-specific behaviors:
  - OIDC discovery at /application/o/<slug>/.well-known/openid-configuration
  - Endpoints mounted under /application/o/ prefix
  - Flow-based login via /api/v3/flows/executor/<slug>/ JSON API
  - Two-phase authorize: authenticate via flow executor, then re-request authorize
  - Standard authorization_code + PKCE flow
"""

import re
import json
import urllib.parse
from typing import Tuple, Optional, Dict

import requests


class AuthentikProtocolMixin:
    """Authentik OAuth2/OIDC protocol mixin for fuzzing.

    Standalone mixin (does NOT inherit from OAuthProtocolBase).
    Mixed into OAuthProtocol via multiple inheritance.
    """

    # ── Endpoint configuration ──────────────────────────────────────

    def _configure_endpoints(self):
        base = self.config.base_url.rstrip('/')
        app_slug = getattr(self.config, '_authentik_app_slug', 'fuzz-app')

        # Try application-specific OIDC discovery first
        discovery_url = f"{base}/application/o/{app_slug}/.well-known/openid-configuration"
        discovered = {}
        try:
            r = requests.get(discovery_url, timeout=5,
                             headers={'Accept': 'application/json'},
                             verify=False)
            if r.status_code == 200:
                discovered = r.json()
                print(f"[OIDC Discovery] Authentik endpoints from {discovery_url}")
        except Exception as e:
            print(f"[OIDC Discovery] Authentik fallback (reason: {e})")

        # Apply discovered endpoints or fall back to hardcoded Authentik paths
        self.auth_endpoint = discovered.get(
            'authorization_endpoint',
            f"{base}/application/o/authorize/")
        self.token_endpoint = discovered.get(
            'token_endpoint',
            f"{base}/application/o/token/")
        self.userinfo_endpoint = discovered.get(
            'userinfo_endpoint',
            f"{base}/application/o/userinfo/")
        self.introspect_endpoint = discovered.get(
            'introspection_endpoint',
            f"{base}/application/o/introspect/")
        self.revoke_endpoint = discovered.get(
            'revocation_endpoint',
            f"{base}/application/o/revoke/")
        self.end_session_endpoint = discovered.get(
            'end_session_endpoint',
            f"{base}/application/o/{app_slug}/end-session/")
        self.jwks_endpoint = discovered.get(
            'jwks_uri',
            f"{base}/application/o/{app_slug}/jwks/")
        self.device_endpoint = discovered.get(
            'device_authorization_endpoint',
            f"{base}/application/o/device/")
        self.discovery_url = discovery_url

        for attr, default in (
            ('device_authorize_endpoint', self.device_endpoint),
            ('registration_endpoint', None),
            ('par_endpoint', discovered.get(
                'pushed_authorization_request_endpoint', None)),
        ):
            if not hasattr(self, attr):
                setattr(self, attr, default)

        # Flow executor base URL (populated during authorize())
        self._authentik_base = base

    # ── authorize ──────────────────────────────────────────────────

    def authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        """GET /application/o/authorize/ to start the OAuth2 flow.

        Authentik redirects unauthenticated users to a login flow.
        We capture the flow URL (do NOT follow redirects) so the login
        method can authenticate via the flow executor API.
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
            self._authentik_auth_params = params

            if resp.status_code in (302, 303):
                location = resp.headers.get('Location', '')
                self.last_location = location
                self.login_form_url = location

                # Extract flow slug and query string for executor API
                self._parse_flow_url(location)

                # If already authenticated, location may contain code=
                if 'code=' in location:
                    code = self._extract_auth_code(location)
                    if code:
                        self.auth_code = code

            elif resp.status_code == 200:
                # Already authenticated, response body may have form
                self.login_form_url = url

            return 'authorize', resp
        except Exception as e:
            return 'authorize_error', self._synthetic_response(500, str(e))

    # ── login ──────────────────────────────────────────────────────

    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        """Authenticate via Authentik's flow executor API, then re-request
        the authorize endpoint to obtain the auth code.

        The flow has two stages:
          1. ak-stage-identification (submit username)
          2. ak-stage-password (submit password)
        After completing the flow, we re-hit the authorize endpoint.
        The authenticated session gets redirected to the callback with code=.
        """
        exec_url = getattr(self, '_authentik_exec_url', None)
        if not exec_url:
            return 'login_error', self._synthetic_response(
                400, 'No flow executor URL (run authorize() first)')

        username = kwargs.get('username', self.config.username)
        password = kwargs.get('password', self.config.password)
        base = self._authentik_base

        try:
            # Stage 1: Identification
            r1 = self.session.post(
                exec_url,
                json={'component': 'ak-stage-identification', 'uid_field': username},
                headers={'Accept': 'application/json'},
                allow_redirects=False, timeout=10, verify=False)
            self._track_response(r1)

            if r1.status_code == 302:
                loc = r1.headers['Location']
                self.session.get(
                    loc if loc.startswith('http') else f"{base}{loc}",
                    headers={'Accept': 'application/json'},
                    allow_redirects=False, timeout=10, verify=False)

            # Stage 2: Password
            r2 = self.session.post(
                exec_url,
                json={'component': 'ak-stage-password', 'password': password},
                headers={'Accept': 'application/json'},
                allow_redirects=False, timeout=10, verify=False)
            self._track_response(r2)

            # Follow redirect chain to complete the flow
            for _ in range(5):
                if r2.status_code != 302:
                    break
                loc = r2.headers.get('Location', '')
                if not loc:
                    break
                r2 = self.session.get(
                    loc if loc.startswith('http') else f"{base}{loc}",
                    headers={'Accept': 'application/json'},
                    allow_redirects=False, timeout=10, verify=False)
                self._track_response(r2)

            # Now re-request authorize with the authenticated session
            auth_params = getattr(self, '_authentik_auth_params', {})
            if auth_params:
                auth_url = f"{self.auth_endpoint}?{urllib.parse.urlencode(auth_params)}"
            else:
                auth_url = self.auth_endpoint

            r3 = self.session.get(
                auth_url, allow_redirects=False,
                timeout=10, verify=False)
            self._track_request('GET', auth_url, dict(self.session.headers))
            self._track_response(r3)
            loc3 = r3.headers.get('Location', '')

            # If redirected to authorization flow (consent), complete it
            if r3.status_code in (302, 303) and '/if/flow/' in loc3:
                consent_url = loc3 if loc3.startswith('http') else f"{base}{loc3}"
                self._parse_flow_url(consent_url)
                consent_exec = getattr(self, '_authentik_exec_url', None)
                if consent_exec:
                    r4 = self.session.get(
                        consent_exec,
                        headers={'Accept': 'application/json'},
                        allow_redirects=False, timeout=10, verify=False)
                    self._track_response(r4)
                    try:
                        data = r4.json()
                        comp = data.get('component', '')
                        r5 = self.session.post(
                            consent_exec,
                            json={'component': comp},
                            headers={'Accept': 'application/json'},
                            allow_redirects=False, timeout=10, verify=False)
                        self._track_response(r5)
                        for j in range(8):
                            if r5.status_code == 302:
                                loc5 = r5.headers.get('Location', '')
                                if 'code=' in loc5:
                                    code = self._extract_auth_code(loc5)
                                    if code:
                                        self.auth_code = code
                                        self.last_location = loc5
                                    break
                                r5 = self.session.get(
                                    loc5 if loc5.startswith('http') else f"{base}{loc5}",
                                    headers={'Accept': 'application/json'},
                                    allow_redirects=False, timeout=10, verify=False)
                                self._track_response(r5)
                            else:
                                try:
                                    d = r5.json()
                                    if d.get('component') == 'xak-flow-redirect':
                                        redir = d.get('to', '')
                                        r6 = self.session.get(
                                            redir if redir.startswith('http') else f"{base}{redir}",
                                            allow_redirects=False, timeout=10, verify=False)
                                        self._track_response(r6)
                                        if r6.status_code in (302, 303):
                                            loc6 = r6.headers.get('Location', '')
                                            if 'code=' in loc6:
                                                code = self._extract_auth_code(loc6)
                                                if code:
                                                    self.auth_code = code
                                                    self.last_location = loc6
                                except Exception:
                                    pass
                                break
                    except Exception:
                        pass

            if 'code=' in (loc3 or ''):
                code = self._extract_auth_code(loc3)
                if code:
                    self.auth_code = code
                    self.last_location = loc3

            return 'login', r3
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

    # ── auth_code_redirect ─────────────────────────────────────────

    def auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Extract the authorization code.

        For Authentik, the code is obtained during login() via the
        re-requested authorize endpoint. If already captured, return
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

        base = self._authentik_base
        for _ in range(8):
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

    # ── Authentik-specific attack methods ──────────────────────────

    def authentik_flow_stage_bypass(self, **kwargs) -> Tuple[str, requests.Response]:
        """POST directly to flow executor without completing prior stages."""
        base = self._authentik_base
        # Use a fresh flow executor URL (not the one from authorize)
        flow_slug = 'default-authentication-flow'
        exec_url = f"{base}/api/v3/flows/executor/{flow_slug}/"

        try:
            # Skip identification, go straight to password
            resp = self.session.post(
                exec_url,
                json={'component': 'ak-stage-password',
                      'password': kwargs.get('password', 'bypass-test')},
                headers={'Accept': 'application/json'},
                allow_redirects=False, timeout=10, verify=False)
            self._track_response(resp)
            return 'authentik_flow_stage_bypass', resp
        except Exception as e:
            return 'authentik_flow_stage_bypass_error', self._synthetic_response(500, str(e))

    def authentik_csrf_token_reuse(self, **kwargs) -> Tuple[str, requests.Response]:
        """Attempt to reuse a flow executor session across new flows.

        Tests if Authentik properly isolates flow sessions.
        """
        exec_url = getattr(self, '_authentik_exec_url', None)
        if not exec_url:
            return 'authentik_csrf_token_reuse_error', self._synthetic_response(
                400, 'No flow executor URL available')

        # Try submitting to the SAME flow executor URL with fresh credentials
        try:
            resp = self.session.post(
                exec_url,
                json={'component': 'ak-stage-identification',
                      'uid_field': kwargs.get('username', 'admin')},
                headers={'Accept': 'application/json'},
                allow_redirects=False, timeout=10, verify=False)
            self._track_response(resp)
            return 'authentik_csrf_token_reuse', resp
        except Exception as e:
            return 'authentik_csrf_token_reuse_error', self._synthetic_response(500, str(e))

    def authentik_device_code_fuzz(self, **kwargs) -> Tuple[str, requests.Response]:
        """POST to /application/o/device/ with malformed payloads."""
        device_url = getattr(self, 'device_endpoint',
                             f"{self._authentik_base}/application/o/device/")

        test_case = kwargs.get('test_case', 'missing_client_id')
        payloads = {
            'missing_client_id': {'scope': self.config.scope},
            'empty_scope': {'client_id': self.config.client_id, 'scope': ''},
            'oversized_scope': {'client_id': self.config.client_id, 'scope': 'openid ' * 500},
            'special_chars_scope': {
                'client_id': self.config.client_id,
                'scope': 'openid<script>alert(1)</script>\x00profile'},
        }
        data = payloads.get(test_case, {
            'client_id': self.config.client_id,
            'scope': self.config.scope})
        if self.config.client_secret and 'client_secret' not in data:
            data['client_secret'] = self.config.client_secret

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'}
        try:
            resp = self.session.post(device_url, data=data, headers=headers,
                                     timeout=10, verify=False)
            self._track_response(resp)
            return 'authentik_device_code_fuzz', resp
        except Exception as e:
            return 'authentik_device_code_fuzz_error', self._synthetic_response(500, str(e))

    def authentik_introspect_cross_client(self, **kwargs) -> Tuple[str, requests.Response]:
        """Introspect a token using different (wrong) client credentials."""
        if not self.access_token:
            return 'authentik_introspect_cross_client_error', self._synthetic_response(
                400, 'no access_token available')

        cross_id = kwargs.get('cross_client_id', 'evil-cross-client-id')
        cross_secret = kwargs.get('cross_client_secret', 'evil-cross-client-secret')

        data = {
            'token': kwargs.get('token', self.access_token),
            'client_id': cross_id,
            'client_secret': cross_secret,
            'token_type_hint': 'access_token',
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json'}

        if kwargs.get('client_auth') == 'basic':
            import base64
            basic = base64.b64encode(f"{cross_id}:{cross_secret}".encode()).decode()
            headers['Authorization'] = f'Basic {basic}'
            data.pop('client_id', None)
            data.pop('client_secret', None)

        try:
            resp = self.session.post(self.introspect_endpoint, data=data,
                                     headers=headers, timeout=10, verify=False)
            self._track_response(resp)
            return 'authentik_introspect_cross_client', resp
        except Exception as e:
            return 'authentik_introspect_cross_client_error', self._synthetic_response(500, str(e))

    def authentik_token_confusion(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test token type confusion: use refresh_token as Bearer or access_token as refresh."""
        test_type = kwargs.get('test_type', 'refresh_as_bearer')

        if test_type == 'refresh_as_bearer':
            token = kwargs.get('token', self.refresh_token_value)
            if not token:
                return 'authentik_token_confusion_error', self._synthetic_response(
                    400, 'no refresh_token available')
            headers = {'Authorization': f'Bearer {token}', 'Accept': 'application/json'}
            try:
                resp = self.session.get(self.userinfo_endpoint, headers=headers,
                                        timeout=10, verify=False)
                self._track_response(resp)
                return 'authentik_token_confusion', resp
            except Exception as e:
                return 'authentik_token_confusion_error', self._synthetic_response(500, str(e))

        elif test_type == 'access_as_refresh':
            token = kwargs.get('token', self.access_token)
            if not token:
                return 'authentik_token_confusion_error', self._synthetic_response(
                    400, 'no access_token available')
            data = {
                'grant_type': 'refresh_token',
                'refresh_token': token,
                'client_id': self.config.client_id,
            }
            if self.config.client_secret:
                data['client_secret'] = self.config.client_secret
            headers = {'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'application/json'}
            try:
                resp = self.session.post(self.token_endpoint, data=data,
                                         headers=headers, timeout=10, verify=False)
                self._track_response(resp)
                return 'authentik_token_confusion', resp
            except Exception as e:
                return 'authentik_token_confusion_error', self._synthetic_response(500, str(e))

        return 'authentik_token_confusion_error', self._synthetic_response(
            400, f'unknown test_type: {test_type}')

    def authentik_scope_escalation(self, **kwargs) -> Tuple[str, requests.Response]:
        """Request authorize with escalated admin-level scopes."""
        escalated = kwargs.get('scopes', [
            'openid profile email authentik_admin',
            'openid authentik_providers_all',
        ])
        scope = escalated[0] if isinstance(escalated, list) else escalated
        self._ensure_state_pkce()

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

        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        try:
            resp = self.session.get(url, allow_redirects=False,
                                    timeout=10, verify=False)
            self._track_response(resp)
            return 'authentik_scope_escalation', resp
        except Exception as e:
            return 'authentik_scope_escalation_error', self._synthetic_response(500, str(e))

    def authentik_end_session_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """GET end-session with malicious post_logout_redirect_uri values."""
        base = self._authentik_base
        end_session_url = getattr(self, 'end_session_endpoint',
                                  f"{base}/application/o/fuzz-app/end-session/")

        malicious = kwargs.get('redirects', [
            'http://evil.com', '//evil.com', 'javascript:alert(1)',
            'https://evil.com/callback', 'data:text/html,<script>alert(1)</script>',
        ])
        redirect_uri = malicious[0] if isinstance(malicious, list) else malicious

        params = {'post_logout_redirect_uri': redirect_uri}
        if self.id_token:
            params['id_token_hint'] = kwargs.get('id_token_hint', self.id_token)
        if self.state:
            params['state'] = kwargs.get('state', self.state)

        url = f"{end_session_url}?{urllib.parse.urlencode(params)}"
        try:
            resp = self.session.get(url, allow_redirects=False,
                                    timeout=10, verify=False)
            self._track_response(resp)
            return 'authentik_end_session_redirect', resp
        except Exception as e:
            return 'authentik_end_session_redirect_error', self._synthetic_response(500, str(e))

    # ── Internal helpers ────────────────────────────────────────────

    def _parse_flow_url(self, flow_url: str):
        """Extract flow executor URL from the authorize redirect Location."""
        base = self._authentik_base
        if not flow_url:
            self._authentik_exec_url = None
            return

        # Resolve relative URL
        if not flow_url.startswith('http'):
            flow_url = f"{base}{flow_url}"

        # Extract flow slug and query string
        # URL format: .../if/flow/<slug>/?params...
        parts = flow_url.split('?', 1)
        slug_match = re.search(r'/if/flow/([^/]+)', parts[0])
        if slug_match:
            slug = slug_match.group(1)
            qs = ('?' + parts[1]) if len(parts) > 1 else ''
            self._authentik_exec_url = f"{base}/api/v3/flows/executor/{slug}/{qs}"
        else:
            self._authentik_exec_url = None

    def _synthetic_response(self, status: int, text: str) -> requests.Response:
        """Create a synthetic requests.Response for error cases."""
        r = requests.Response()
        r.status_code = status
        r._content = (text or '').encode('utf-8')
        return r
