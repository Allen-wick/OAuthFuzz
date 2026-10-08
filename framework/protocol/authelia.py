#!/usr/bin/env python3
"""[Target]-specific OAuth protocol methods."""

import re
import html
import json
import random
import urllib.parse
import requests
import base64
from typing import Tuple, Dict


class AutheliaProtocolMixin:
    # ====== AUTHELIA-SPECIFIC METHODS (MEDIUM PRIORITY) ======
    
    def authelia_auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia auth code redirect — re-requests the authorization endpoint
        after first-factor authentication to obtain the auth code.
        
        Authelia flow:
        1. authelia_authorize() → establishes session
        2. authelia_login() → POST /api/firstfactor (authenticates)
        3. authelia_auth_code_redirect() → re-GET authorization endpoint → redirect with code
        4. token_exchange() → exchange code for tokens
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
        
        if self.code_challenge and 'code_challenge' not in kwargs:
            params['code_challenge'] = self.code_challenge
            params['code_challenge_method'] = kwargs.get('code_challenge_method', 'S256')
        
        auth_endpoint = getattr(self, 'auth_endpoint', f"{self.config.base_url}/api/oidc/authorization")
        url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
        
        headers = self.session.headers.copy()
        headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        })
        
        self._track_request('GET', url, headers)
        
        response = self.session.get(
            url,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        
        if response.status_code in (302, 303):
            location = response.headers.get('Location', '')
            code = self._extract_auth_code(location)
            if code:
                self.auth_code = code
                self.last_location = location
        elif response.status_code == 200:
            try:
                body = response.json()
                redirect_url = body.get('redirect_uri', '')
                if redirect_url:
                    code = self._extract_auth_code(redirect_url)
                    if code:
                        self.auth_code = code
                        self.last_location = redirect_url
            except Exception:
                pass
        
        return 'authelia_auth_code_redirect', response
    
    def authelia_authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia-specific authorize that establishes session and initiates OAuth flow.
        Unlike Keycloak, Authelia requires session establishment before authentication.
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
        
        # Add PKCE if configured
        if self.code_challenge and 'code_challenge' not in kwargs:
            params['code_challenge'] = self.code_challenge
            params['code_challenge_method'] = kwargs.get('code_challenge_method', 'S256')
        
        auth_endpoint = getattr(self, 'auth_endpoint', f"{self.config.base_url}/api/oidc/authorization")
        url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
        
        headers = self.session.headers.copy()
        headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-Agent': 'OAuthFuzzer/1.0'
        })
        
        self._track_request('GET', url, headers)
        
        # Allow redirects to establish session cookies
        response = self.session.get(
            url,
            headers=headers,
            allow_redirects=True,
            verify=False
        )
        
        self._track_response(response)
        
        # Store the target URL for firstfactor/login
        self._authelia_target_url = url
        self.login_form_url = url
        self.login_referer_url = url
        
        return 'authelia_authorize', response
    
    def authelia_login(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia-specific login using JSON API (/api/firstfactor).
        Must be called after authelia_authorize to have valid session.
        """
        endpoint = getattr(self, 'firstfactor_endpoint', 
                          f"{self.config.base_url}/api/firstfactor")
        
        username = kwargs.get('username', self.config.username)
        password = kwargs.get('password', self.config.password)
        keepMeLoggedIn = kwargs.get('keepMeLoggedIn', False)
        
        # Use stored target URL or build one
        target_url = getattr(self, '_authelia_target_url', None)
        if not target_url:
            self._ensure_state_pkce()
            params = {
                'response_type': 'code',
                'client_id': self.config.client_id,
                'redirect_uri': self.config.redirect_uri,
                'scope': self.config.scope,
                'state': self.state,
                'nonce': self.nonce,
            }
            if self.code_challenge:
                params['code_challenge'] = self.code_challenge
                params['code_challenge_method'] = 'S256'
            auth_endpoint = getattr(self, 'auth_endpoint', f"{self.config.base_url}/api/oidc/authorization")
            target_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
        
        data = {
            'username': username,
            'password': password,
            'keepMeLoggedIn': keepMeLoggedIn,
            'targetURL': kwargs.get('targetURL', target_url)
        }
        
        headers = self.session.headers.copy()
        headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Origin': self.config.base_url,
            'Referer': target_url
        })
        
        self._track_request('POST', endpoint, headers, data)
        
        response = self.session.post(
            endpoint,
            json=data,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        
        # Mark authentication complete if successful (200 OK)
        if response.status_code == 200:
            self._authelia_authenticated = True
        
        return 'authelia_login', response

    def authelia_firstfactor(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia first factor authentication.
        Tests the /api/firstfactor endpoint for credential verification.
        """
        endpoint = getattr(self, 'firstfactor_endpoint', 
                          f"{self.config.base_url}/api/firstfactor")
        
        username = kwargs.get('username', self.config.username)
        password = kwargs.get('password', self.config.password)
        keepMeLoggedIn = kwargs.get('keepMeLoggedIn', False)
        targetURL = kwargs.get('targetURL', self.config.redirect_uri)
        
        data = {
            'username': username,
            'password': password,
            'keepMeLoggedIn': keepMeLoggedIn,
            'targetURL': targetURL
        }
        
        headers = self.session.headers.copy()
        headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        self._track_request('POST', endpoint, headers, data)
        
        response = self.session.post(
            endpoint,
            json=data,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_firstfactor', response
    
    def authelia_secondfactor_totp(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia second factor TOTP authentication.
        Tests the /api/secondfactor/totp endpoint.
        """
        endpoint = getattr(self, 'secondfactor_totp_endpoint',
                          f"{self.config.base_url}/api/secondfactor/totp")
        
        # TOTP code - use provided or generate test patterns
        totp_code = kwargs.get('token', '000000')  # Test with invalid/pattern codes
        targetURL = kwargs.get('targetURL', self.config.redirect_uri)
        
        data = {
            'token': totp_code,
            'targetURL': targetURL
        }
        
        headers = self.session.headers.copy()
        headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        self._track_request('POST', endpoint, headers, data)
        
        response = self.session.post(
            endpoint,
            json=data,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_secondfactor_totp', response
    
    def authelia_secondfactor_webauthn(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia second factor WebAuthn authentication.
        Tests the /api/secondfactor/webauthn endpoint.
        """
        endpoint = getattr(self, 'secondfactor_webauthn_endpoint',
                          f"{self.config.base_url}/api/secondfactor/webauthn")
        
        # WebAuthn assertion - test with malformed data
        assertion_data = kwargs.get('assertion', {
            'id': 'test-credential-id',
            'rawId': 'dGVzdC1jcmVkZW50aWFsLWlk',
            'response': {
                'authenticatorData': 'test-authenticator-data',
                'clientDataJSON': 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=',
                'signature': 'test-signature'
            },
            'type': 'public-key'
        })
        
        headers = self.session.headers.copy()
        headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        self._track_request('POST', endpoint, headers, assertion_data)
        
        response = self.session.post(
            endpoint,
            json=assertion_data,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_secondfactor_webauthn', response
    
    def authelia_consent(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia OIDC consent handling.
        Tests the consent endpoint for authorization.
        """
        endpoint = getattr(self, 'consent_endpoint',
                          f"{self.config.base_url}/api/oidc/consent")
        
        consent_id = kwargs.get('id', '')
        accept = kwargs.get('accept', True)
        
        data = {
            'id': consent_id,
            'accept': accept
        }
        
        headers = self.session.headers.copy()
        headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        self._track_request('POST', endpoint, headers, data)
        
        response = self.session.post(
            endpoint,
            json=data,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_consent', response
    
    def authelia_logout(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia logout endpoint.
        Tests session termination.
        """
        endpoint = getattr(self, 'logout_endpoint',
                          f"{self.config.base_url}/api/logout")
        
        headers = self.session.headers.copy()
        headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        self._track_request('POST', endpoint, headers, {})
        
        response = self.session.post(
            endpoint,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_logout', response
    
    def authelia_state(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia state endpoint.
        Queries authentication state for current session.
        """
        endpoint = getattr(self, 'state_endpoint',
                          f"{self.config.base_url}/api/state")
        
        headers = self.session.headers.copy()
        headers.update({
            'Accept': 'application/json'
        })
        
        self._track_request('GET', endpoint, headers)
        
        response = self.session.get(
            endpoint,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_state', response
    
    def authelia_configuration(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Authelia configuration endpoint.
        Queries public configuration (may expose sensitive info).
        """
        endpoint = getattr(self, 'configuration_endpoint',
                          f"{self.config.base_url}/api/configuration")
        
        headers = self.session.headers.copy()
        headers.update({
            'Accept': 'application/json'
        })
        
        self._track_request('GET', endpoint, headers)
        
        response = self.session.get(
            endpoint,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_configuration', response
    
    def authelia_firstfactor_bypass(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Attempt to bypass first factor authentication.
        Tests direct access to protected resources without authentication.
        """
        # Try to access consent/authorization directly without first factor
        endpoint = getattr(self, 'consent_endpoint',
                          f"{self.config.base_url}/api/oidc/consent")
        
        # Clear any existing session
        old_cookies = dict(self.session.cookies)
        self.session.cookies.clear()
        
        headers = self.session.headers.copy()
        headers.update({
            'Accept': 'application/json'
        })
        
        self._track_request('GET', endpoint, headers)
        
        response = self.session.get(
            endpoint,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        # Restore cookies
        for name, value in old_cookies.items():
            self.session.cookies.set(name, value)
        
        self._track_response(response)
        return 'authelia_firstfactor_bypass', response
    
    def authelia_2fa_bypass(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Attempt to bypass second factor authentication.
        Tests access to OIDC endpoints with only first factor complete.
        """
        # First, complete first factor
        self.authelia_firstfactor(**kwargs)
        
        # Then try to access authorization without 2FA
        self._ensure_state_pkce()
        
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scope,
            'state': self.state,
            'nonce': self.nonce,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256'
        }
        
        endpoint = getattr(self, 'auth_endpoint',
                          f"{self.config.base_url}/api/oidc/authorization")
        
        self._track_request('GET', endpoint, dict(self.session.headers), params)
        
        response = self.session.get(
            endpoint,
            params=params,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_2fa_bypass', response
    
    def authelia_consent_bypass(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Attempt to bypass consent screen.
        Tests direct token request without user consent.
        """
        # Complete first factor
        self.authelia_firstfactor(**kwargs)
        
        # Try to exchange code directly without consent
        token_endpoint = getattr(self, 'token_endpoint',
                                f"{self.config.base_url}/api/oidc/token")
        
        # Use a fake auth code to test bypass
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'redirect_uri': self.config.redirect_uri,
            'code': 'fake_auth_code_bypass_attempt',
            'code_verifier': self.code_verifier if self.code_verifier else 'test'
        }
        
        headers = self.session.headers.copy()
        headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        })
        
        self._track_request('POST', token_endpoint, headers, data)
        
        response = self.session.post(
            token_endpoint,
            data=data,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_consent_bypass', response
    
    def authelia_regulation_bypass(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Test Authelia's rate limiting (regulation) mechanism.
        Sends multiple failed auth attempts to test ban behavior.
        """
        endpoint = getattr(self, 'firstfactor_endpoint',
                          f"{self.config.base_url}/api/firstfactor")
        
        # Use invalid credentials to trigger regulation
        data = {
            'username': kwargs.get('username', 'invalid_user'),
            'password': kwargs.get('password', 'wrong_password'),
            'keepMeLoggedIn': False
        }
        
        headers = self.session.headers.copy()
        headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        self._track_request('POST', endpoint, headers, data)
        
        response = self.session.post(
            endpoint,
            json=data,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_regulation_bypass', response
    
    def authelia_session_fixation(self, **kwargs) -> Tuple[str, requests.Response]:
        """
        Test for session fixation vulnerabilities.
        Checks if session ID changes after authentication.
        """
        # Get initial session state
        initial_cookies = dict(self.session.cookies)
        
        # Perform first factor authentication
        self.authelia_firstfactor(**kwargs)
        
        # Check if session changed
        post_auth_cookies = dict(self.session.cookies)
        
        # Query state to verify session
        endpoint = getattr(self, 'state_endpoint',
                          f"{self.config.base_url}/api/state")
        
        headers = self.session.headers.copy()
        headers.update({
            'Accept': 'application/json',
            'X-Initial-Cookies': json.dumps(list(initial_cookies.keys())),
            'X-PostAuth-Cookies': json.dumps(list(post_auth_cookies.keys()))
        })
        
        self._track_request('GET', endpoint, headers)
        
        response = self.session.get(
            endpoint,
            headers=headers,
            allow_redirects=False,
            verify=False
        )
        
        self._track_response(response)
        return 'authelia_session_fixation', response

    # ====== AUDIT-PACK SYMBOLS (SECURITY_AUDIT.md §7) ======

    def _audit_base_url(self) -> str:
        return getattr(self.config, 'base_url', 'https://localhost:9091')

    def authelia_consent_id_fuzz(self, **kwargs) -> Tuple[str, requests.Response]:
        """B2/S2 — POST /api/oidc/consent with malformed flow_id and forged consent_id.
        Expects 4xx, no panic / 500.
        """
        endpoint = getattr(self, 'consent_endpoint',
                           f"{self._audit_base_url()}/api/oidc/consent")
        bad_flow_ids = [
            'not-a-uuid', '00000000-0000-0000-0000-000000000000',
            '../../../etc/passwd', 'A' * 4096,
            '%00%00%00%00', 'null', '{"$ne":null}',
        ]
        payload = {
            'flow_id': kwargs.get('flow_id', random.choice(bad_flow_ids)),
            'client_id': kwargs.get('client_id', self.config.client_id),
            'consent': True,
            'pre_configure': False,
            'consent_id': kwargs.get('consent_id', '11111111-1111-1111-1111-111111111111'),
        }
        headers = self.session.headers.copy()
        headers.update({'Accept': 'application/json',
                        'Content-Type': 'application/json'})
        self._track_request('POST', endpoint, headers, payload)
        response = self.session.post(endpoint, json=payload, headers=headers,
                                     allow_redirects=False, verify=False)
        self._track_response(response)
        return 'authelia_consent_id_fuzz', response

    def authelia_par_flood(self, **kwargs) -> Tuple[str, requests.Response]:
        """B1/B3 — PAR endpoint flooded with oversize JWT-shaped body.
        Probes for 5xx / OOM in pushed authorization request handler.
        """
        endpoint = getattr(self, 'par_endpoint',
                           f"{self._audit_base_url()}/api/oidc/pushed-authorization-request")
        nested = {'a': 'x' * 1024}
        for _ in range(64):
            nested = {'n': nested}
        request_jwt_body = base64.urlsafe_b64encode(
            json.dumps(nested).encode()).decode().rstrip('=')
        large_payload = {
            'client_id': self.config.client_id,
            'response_type': 'code',
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scope,
            'state': 'A' * (kwargs.get('state_len', 8192)),
            'nonce': 'B' * (kwargs.get('nonce_len', 8192)),
            'request': f"eyJhbGciOiJub25lIn0.{request_jwt_body}.",
            'code_challenge': 'C' * 4096,
            'code_challenge_method': 'plain',
        }
        headers = self.session.headers.copy()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'application/json'})
        self._track_request('POST', endpoint, headers, large_payload)
        response = self.session.post(endpoint, data=large_payload, headers=headers,
                                     allow_redirects=False, verify=False, timeout=10)
        self._track_response(response)
        return 'authelia_par_flood', response

    def authelia_authorize_after_1fa(self, **kwargs) -> Tuple[str, requests.Response]:
        """S1/S4 — issue OIDC authorize after only 1FA; must NOT bypass to consent.
        Expected: redirect to 2FA UI or 401.
        """
        try:
            self.authelia_login(**kwargs)
        except Exception:
            pass
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scope,
            'state': getattr(self, 'state', 'audit-state'),
            'nonce': getattr(self, 'nonce', 'audit-nonce'),
            'prompt': 'none',
        }
        if getattr(self, 'code_challenge', None):
            params['code_challenge'] = self.code_challenge
            params['code_challenge_method'] = 'S256'
        auth_endpoint = getattr(self, 'auth_endpoint',
                                f"{self._audit_base_url()}/api/oidc/authorization")
        url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
        headers = self.session.headers.copy()
        headers['Accept'] = 'text/html'
        self._track_request('GET', url, headers)
        response = self.session.get(url, headers=headers,
                                    allow_redirects=False, verify=False)
        self._track_response(response)
        return 'authelia_authorize_after_1fa', response

    def authelia_consent_subject_swap(self, **kwargs) -> Tuple[str, requests.Response]:
        """S3 — POST /api/oidc/consent with body subject differing from session.
        Server must derive subject from session, not body.
        """
        endpoint = getattr(self, 'consent_endpoint',
                           f"{self._audit_base_url()}/api/oidc/consent")
        payload = {
            'flow_id': kwargs.get('flow_id', '22222222-2222-2222-2222-222222222222'),
            'client_id': kwargs.get('client_id', self.config.client_id),
            'consent': True,
            'pre_configure': True,
            'subject': kwargs.get('subject', 'admin'),
            'sub': 'admin',
            'username': 'admin',
        }
        headers = self.session.headers.copy()
        headers.update({'Accept': 'application/json',
                        'Content-Type': 'application/json'})
        self._track_request('POST', endpoint, headers, payload)
        response = self.session.post(endpoint, json=payload, headers=headers,
                                     allow_redirects=False, verify=False)
        self._track_response(response)
        return 'authelia_consent_subject_swap', response

    def authelia_session_regen_check(self, **kwargs) -> Tuple[str, requests.Response]:
        """S4/E1 — capture pre-auth cookie, complete 1FA, then probe /api/state with
        the original cookie; expects authentication_level == 0.
        """
        pre_cookies = dict(self.session.cookies)
        try:
            self.authelia_login(**kwargs)
        except Exception:
            pass
        replay = requests.Session()
        replay.verify = False
        for k, v in pre_cookies.items():
            replay.cookies.set(k, v)
        endpoint = getattr(self, 'state_endpoint',
                           f"{self._audit_base_url()}/api/state")
        headers = {'Accept': 'application/json',
                   'X-Audit-Symbol': 'AutheliaSessionRegenCheck'}
        self._track_request('GET', endpoint, headers)
        response = replay.get(endpoint, headers=headers,
                              allow_redirects=False, verify=False)
        self._track_response(response)
        return 'authelia_session_regen_check', response

    def authelia_pkce_method_confusion(self, **kwargs) -> Tuple[str, requests.Response]:
        """S5 — authorize with code_challenge_method=plain against a client that
        should require S256. Followup token exchange uses code_verifier == challenge.
        """
        challenge = kwargs.get('code_challenge', 'audit-challenge-' + str(random.randint(0, 1 << 30)))
        self.code_challenge = challenge
        self.code_verifier = challenge  # plain == challenge
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scope,
            'state': getattr(self, 'state', 'pkce-state'),
            'nonce': getattr(self, 'nonce', 'pkce-nonce'),
            'code_challenge': challenge,
            'code_challenge_method': 'plain',
        }
        auth_endpoint = getattr(self, 'auth_endpoint',
                                f"{self._audit_base_url()}/api/oidc/authorization")
        url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
        headers = self.session.headers.copy()
        headers['Accept'] = 'text/html'
        self._track_request('GET', url, headers)
        response = self.session.get(url, headers=headers,
                                    allow_redirects=False, verify=False)
        self._track_response(response)
        return 'authelia_pkce_method_confusion', response

    def authelia_redirect_mismatch_token(self, **kwargs) -> Tuple[str, requests.Response]:
        """M2 — token exchange with redirect_uri differing by one byte from authorize-time.
        Expects invalid_grant.
        """
        code = kwargs.get('code', getattr(self, 'auth_code', 'AUDIT-CODE'))
        original = self.config.redirect_uri
        if original.endswith('/'):
            mutated = original[:-1] + 'X/'
        else:
            mutated = original + 'X'
        endpoint = getattr(self, 'token_endpoint',
                           f"{self._audit_base_url()}/api/oidc/token")
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': mutated,
            'client_id': self.config.client_id,
            'client_secret': getattr(self.config, 'client_secret', ''),
        }
        if getattr(self, 'code_verifier', None):
            payload['code_verifier'] = self.code_verifier
        headers = self.session.headers.copy()
        headers.update({'Content-Type': 'application/x-www-form-urlencoded',
                        'Accept': 'application/json'})
        self._track_request('POST', endpoint, headers, payload)
        response = self.session.post(endpoint, data=payload, headers=headers,
                                     allow_redirects=False, verify=False)
        self._track_response(response)
        return 'authelia_redirect_mismatch_token', response

    def authelia_introspect_cross_client(self, **kwargs) -> Tuple[str, requests.Response]:
        """M3/M4 — introspect an access token using a different client's credentials.
        Expects active=false or 401.
        """
        access_token = kwargs.get('access_token', getattr(self, 'access_token', 'AUDIT-AT'))
        other_client = kwargs.get('cross_client_id', 'audit-other-client')
        other_secret = kwargs.get('cross_client_secret', 'audit-other-secret')
        endpoint = getattr(self, 'introspection_endpoint',
                           f"{self._audit_base_url()}/api/oidc/introspection")
        payload = {'token': access_token, 'token_type_hint': 'access_token'}
        basic = base64.b64encode(f"{other_client}:{other_secret}".encode()).decode()
        headers = self.session.headers.copy()
        headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
            'Authorization': f'Basic {basic}',
        })
        self._track_request('POST', endpoint, headers, payload)
        response = self.session.post(endpoint, data=payload, headers=headers,
                                     allow_redirects=False, verify=False)
        self._track_response(response)
        return 'authelia_introspect_cross_client', response

    def authelia_userinfo_alg_none(self, **kwargs) -> Tuple[str, requests.Response]:
        """M5/E4 — request UserInfo with Accept: application/jwt and probe for
        alg:none JWS being returned.
        """
        access_token = kwargs.get('access_token', getattr(self, 'access_token', 'AUDIT-AT'))
        endpoint = getattr(self, 'userinfo_endpoint',
                           f"{self._audit_base_url()}/api/oidc/userinfo")
        headers = self.session.headers.copy()
        headers.update({
            'Accept': 'application/jwt, application/json;q=0.5',
            'Authorization': f'Bearer {access_token}',
            'X-Audit-Symbol': 'AutheliaUserinfoAlgNone',
        })
        self._track_request('GET', endpoint, headers)
        response = self.session.get(endpoint, headers=headers,
                                    allow_redirects=False, verify=False)
        self._track_response(response)
        return 'authelia_userinfo_alg_none', response

    def authelia_forward_auth_spoof(self, **kwargs) -> Tuple[str, requests.Response]:
        """E3 — call the forward-auth verify endpoint with injected X-Forwarded-*.
        Compares response variance with header content to detect direct trust.
        """
        endpoint = getattr(self, 'verify_endpoint',
                           f"{self._audit_base_url()}/api/verify?auth=forward")
        spoofed_host = kwargs.get('spoof_host', 'admin.internal.lan')
        spoofed_uri = kwargs.get('spoof_uri', '/admin/users/delete?id=1')
        headers = self.session.headers.copy()
        headers.update({
            'Accept': 'application/json',
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Host': spoofed_host,
            'X-Forwarded-URI': spoofed_uri,
            'X-Forwarded-Method': kwargs.get('spoof_method', 'DELETE'),
            'X-Forwarded-For': kwargs.get('spoof_ip', '127.0.0.1'),
            'X-Original-URL': spoofed_uri,
            'X-Audit-Symbol': 'AutheliaForwardAuthSpoof',
        })
        self._track_request('GET', endpoint, headers)
        response = self.session.get(endpoint, headers=headers,
                                    allow_redirects=False, verify=False)
        self._track_response(response)
        return 'authelia_forward_auth_spoof', response