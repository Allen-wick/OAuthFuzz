#!/usr/bin/env python3
"""
Abstract base class for OAuth protocol implementations.
Each target (Keycloak, Authelia, Spring AS, Apache CXF, WSO2 IS) provides a concrete implementation via mixins.
"""

import requests
import secrets
import hashlib
import base64
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import urllib.parse
import re
import time
import html
import json
import random
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple, Any
from requests import Response


class OAuthProtocolBase(ABC):
    """
    Abstract OAuth/OIDC protocol handler.

    Subclasses (mixins) implement target-specific login flows while sharing
    common OAuth operations (token exchange, userinfo, etc.).
    """

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.verify = False
        self._setup_session_headers()

        self.state = None
        self.nonce = None
        self.code_verifier = None
        self.code_challenge = None
        self.csrf_token = None
        self.auth_code = None
        self.access_token = None
        self.refresh_token_value = None
        self.id_token = None
        self.last_location = None
        self.login_form_url = None
        self.login_referer_url = None

        self.sent_data: List[Dict] = []
        self.received_data: List[Dict] = []
        self.action_meta: Dict = {}

        self._configure_endpoints()

    def _setup_session_headers(self):
        self.session.headers.update({
            'User-Agent': 'OAuthFuzzer/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

    @abstractmethod
    def _configure_endpoints(self):
        ...

    @abstractmethod
    def authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        ...

    @abstractmethod
    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        ...

    @abstractmethod
    def auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        ...

    def reset(self):
        self.session = requests.Session()
        self.session.verify = False
        self._setup_session_headers()
        self.state = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(32)
        self.code_verifier = secrets.token_urlsafe(32)
        self.code_challenge = self._generate_code_challenge(self.code_verifier)
        self.csrf_token = None
        self.auth_code = None
        self.access_token = None
        self.refresh_token_value = None
        self.id_token = None
        self.last_location = None
        self.login_form_url = None
        self.login_referer_url = None
        self.sent_data = []
        self.received_data = []
        self.action_meta = {}

    def _generate_code_challenge(self, code_verifier: str) -> str:
        digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

    def _ensure_state_pkce(self):
        if not self.state:
            self.state = secrets.token_urlsafe(32)
        if not self.nonce:
            self.nonce = secrets.token_urlsafe(32)
        if not self.code_verifier:
            self.code_verifier = secrets.token_urlsafe(32)
        if not self.code_challenge:
            self.code_challenge = self._generate_code_challenge(self.code_verifier)

    def _extract_csrf_token(self, html_content: str) -> Optional[str]:
        if not html_content:
            for ck in ('XSRF-TOKEN', 'XSRF_TOKEN', 'CSRF-TOKEN', 'CSRF_TOKEN'):
                v = self.session.cookies.get(ck)
                if v:
                    return v
            return None

        candidates = set()
        hidden_inputs = self._extract_hidden_inputs(html_content)
        for name, value in hidden_inputs:
            if name:
                candidates.add(name.lower())
            if name and name.lower() in ('kc-post', 'csrf', '_token', 'kc-csrf-token', 'csrftoken', 'csrf_token') and value:
                return value

        patterns = [
            r'<input\b[^>]*name\s*=\s*[\'"]?(kc-post|csrf|_token|kc-csrf-token|csrfToken|csrf_token)[\'"]?[^>]*value\s*=\s*[\'"]([^\'"]+)[\'"][^>]*>',
            r'name\s*=\s*[\'"]?(kc-post|csrf|_token|kc-csrf-token|csrfToken|csrf_token)[\'"]?[^>]*value\s*=\s*[\'"]([^\'"]+)[\'"]',
        ]
        for pattern in patterns:
            match = re.search(pattern, html_content or '', re.IGNORECASE | re.DOTALL)
            if match:
                return html.unescape(match.group(2))

        for ck in ('XSRF-TOKEN', 'XSRF_TOKEN', 'CSRF-TOKEN', 'CSRF_TOKEN'):
            v = self.session.cookies.get(ck)
            if v:
                return v
        return None

    def _extract_hidden_inputs(self, html_content: str) -> List[Tuple[str, str]]:
        if not html_content:
            return []
        results: List[Tuple[str, str]] = []
        try:
            for m in re.finditer(r'<input\b[^>]*>', html_content, re.IGNORECASE | re.DOTALL):
                tag = m.group(0)
                if not re.search(r'type\s*=\s*[\'"]?hidden[\'"]?', tag, re.IGNORECASE):
                    continue
                name_m = re.search(r'name\s*=\s*[\'"]([^\'"]+)[\'"]', tag, re.IGNORECASE)
                val_m = re.search(r'value\s*=\s*[\'"]([^\'"]*)[\'"]', tag, re.IGNORECASE)
                if name_m:
                    name = name_m.group(1)
                    value = html.unescape(val_m.group(1)) if val_m else ''
                    results.append((name, value))
        except Exception:
            pass
        return results

    def _extract_auth_code(self, url: str) -> Optional[str]:
        parsed = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed.query)
        return query_params.get('code', [None])[0]

    def _track_request(self, method: str, url: str, headers: Dict, data: Any = None):
        request_data = {
            'method': method,
            'url': url,
            'headers': dict(headers) if headers else {},
            'data': data,
            'timestamp': time.time()
        }
        self.sent_data.append(request_data)

    def _track_response(self, response: requests.Response):
        content = getattr(response, 'content', b'') or b''
        url = getattr(response, 'url', '') or ''
        headers = dict(getattr(response, 'headers', {}))
        response_data = {
            'status_code': getattr(response, 'status_code', 0),
            'headers': headers,
            'content_length': len(content),
            'url': url,
            'timestamp': time.time()
        }
        try:
            text_preview = getattr(response, 'text', '')
            response_data['body_preview'] = (text_preview or '')[:1200]
        except Exception:
            pass
        self.received_data.append(response_data)

    def consent(self, **kwargs) -> Tuple[str, requests.Response]:
        consent_url = kwargs.get('consent_url', f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/auth")
        consent_data = {
            'kc-post': self.csrf_token or '',
            'consent': kwargs.get('consent', 'Yes')
        }
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        headers['Referer'] = consent_url
        self._track_request('POST', consent_url, headers, consent_data)
        response = self.session.post(consent_url, data=consent_data, allow_redirects=False)
        self._track_response(response)
        return 'consent', response

    def token_exchange(self, **kwargs) -> Tuple[str, requests.Response]:
        token_data = {
            'grant_type': kwargs.get('grant_type', 'authorization_code'),
            'code': kwargs.get('code', self.auth_code),
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
        }
        # Only include code_verifier when it is set — CXF 3.5.x chokes on
        # PKCE params in the token request.  Other targets (Keycloak, SAS,
        # WSO2) always have a truthy code_verifier from
        # _ensure_state_pkce().
        if self.code_verifier:
            token_data['code_verifier'] = self.code_verifier
        client_auth = kwargs.get('client_auth', 'post')
        if 'grant_type' in kwargs:
            token_data['grant_type'] = kwargs['grant_type']
        if 'code' in kwargs:
            token_data['code'] = kwargs['code']
        if 'code_verifier' in kwargs:
            token_data['code_verifier'] = kwargs['code_verifier']
        if 'redirect_uri' in kwargs:
            token_data['redirect_uri'] = kwargs['redirect_uri']
        if self.config.client_secret and client_auth != 'basic':
            token_data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        elif 'client_secret' in token_data:
            token_data.pop('client_secret', None)

        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if self.config.client_secret and client_auth == 'basic':
            sec = kwargs.get('client_secret', self.config.client_secret) or ''
            basic = base64.b64encode(f"{self.config.client_id}:{sec}".encode()).decode()
            headers['Authorization'] = f"Basic {basic}"

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
        return 'token_exchange', response

    def password_grant(self, **kwargs) -> Tuple[str, requests.Response]:
        data = {
            'grant_type': 'password',
            'username': kwargs.get('username', self.config.username),
            'password': kwargs.get('password', self.config.password),
            'client_id': self.config.client_id,
            'scope': kwargs.get('scope', self.config.scope),
        }
        if self.config.client_secret:
            data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        self._track_request('POST', self.token_endpoint, headers, data)
        response = self.session.post(self.token_endpoint, data=data)
        self._track_response(response)
        if response.status_code == 200:
            try:
                tj = response.json()
                self.access_token = tj.get('access_token')
                self.refresh_token_value = tj.get('refresh_token')
                self.id_token = tj.get('id_token')
            except:
                pass
        return 'password_grant', response

    def userinfo(self, **kwargs) -> Tuple[str, requests.Response]:
        headers = self.session.headers.copy()
        token = kwargs.get('access_token', self.access_token)
        if token:
            headers['Authorization'] = f"Bearer {token}"
        if 'authorization' in kwargs:
            headers['Authorization'] = kwargs['authorization']
        headers['Accept'] = 'application/json'
        self._track_request('GET', self.userinfo_endpoint, headers)
        response = self.session.get(self.userinfo_endpoint, headers=headers)
        self._track_response(response)
        return 'userinfo', response

    def refresh_token(self, **kwargs) -> Tuple[str, requests.Response]:
        refresh_data = {
            'grant_type': 'refresh_token',
            'refresh_token': kwargs.get('refresh_token', self.refresh_token_value),
            'client_id': self.config.client_id
        }
        client_auth = kwargs.get('client_auth', 'post')
        if 'refresh_token' in kwargs:
            refresh_data['refresh_token'] = kwargs['refresh_token']
        if self.config.client_secret and client_auth != 'basic':
            refresh_data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if self.config.client_secret and client_auth == 'basic':
            sec = kwargs.get('client_secret', self.config.client_secret) or ''
            basic = base64.b64encode(f"{self.config.client_id}:{sec}".encode()).decode()
            headers['Authorization'] = f"Basic {basic}"
        try:
            self.action_meta['refresh_token'] = {
                'client_auth': client_auth,
                'prev_access_token': self.access_token,
                'prev_refresh_token': self.refresh_token_value,      # NEW — oracle uses this
                'sent_refresh_token': refresh_data['refresh_token']   # NEW — the exact value we sent
            }
        except Exception:
            pass
        self._track_request('POST', self.token_endpoint, headers, refresh_data)
        response = self.session.post(self.token_endpoint, data=refresh_data, headers=headers)
        self._track_response(response)
        if response.status_code == 200:
            try:
                token_response = response.json()
                self.access_token = token_response.get('access_token')
                new_rt = token_response.get('refresh_token')
                try:
                    self.action_meta['refresh_token']['returned_refresh_token'] = new_rt
                    self.action_meta['refresh_token']['rotated'] = (
                        new_rt is not None and new_rt != refresh_data['refresh_token']
                    )
                except Exception:
                    pass
                self.refresh_token_value = new_rt
            except:
                pass
        return 'refresh_token', response

    def revoke_token(self, **kwargs) -> Tuple[str, requests.Response]:
        revoke_data = {
            'token': kwargs.get('token', self.access_token or self.refresh_token_value),
            'client_id': self.config.client_id
        }
        client_auth = kwargs.get('client_auth', 'post')
        if 'token_type_hint' in kwargs:
            revoke_data['token_type_hint'] = kwargs.get('token_type_hint')
        if 'token' in kwargs:
            revoke_data['token'] = kwargs['token']
        if self.config.client_secret and client_auth != 'basic':
            revoke_data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if self.config.client_secret and client_auth == 'basic':
            sec = kwargs.get('client_secret', self.config.client_secret) or ''
            basic = base64.b64encode(f"{self.config.client_id}:{sec}".encode()).decode()
            headers['Authorization'] = f"Basic {basic}"
        token_used = revoke_data.get('token')
        token_kind = 'access' if (token_used and self.access_token and token_used == self.access_token) else (
            'refresh' if (token_used and self.refresh_token_value and token_used == self.refresh_token_value) else 'unknown'
        )
        self.action_meta['revoke_token'] = {
            'client_auth': client_auth,
            'auth_header': ('Basic' if client_auth == 'basic' else 'None'),
            'token_kind': token_kind,
            'token_hint': revoke_data.get('token_type_hint', None),
            'token_value_preview': (str(token_used or '')[:24] if token_used else '')
        }
        self._track_request('POST', self.revoke_endpoint, headers, revoke_data)
        response = self.session.post(self.revoke_endpoint, data=revoke_data, headers=headers)
        self._track_response(response)
        return 'revoke_token', response

    def introspect(self, **kwargs) -> Tuple[str, requests.Response]:
        introspect_data = {
            'token': kwargs.get('token', self.access_token),
            'client_id': self.config.client_id
        }
        client_auth = kwargs.get('client_auth', 'post')
        if 'token' in kwargs:
            introspect_data['token'] = kwargs['token']
        if self.config.client_secret and client_auth != 'basic':
            introspect_data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if self.config.client_secret and client_auth == 'basic':
            sec = kwargs.get('client_secret', self.config.client_secret) or ''
            basic = base64.b64encode(f"{self.config.client_id}:{sec}".encode()).decode()
            headers['Authorization'] = f"Basic {basic}"
        tok = introspect_data.get('token')
        tk = 'access' if (tok and self.access_token and tok == self.access_token) else (
            'refresh' if (tok and self.refresh_token_value and tok == self.refresh_token_value) else 'unknown'
        )
        self.action_meta['introspect'] = {
            'client_auth': client_auth,
            'auth_header': ('Basic' if client_auth == 'basic' else 'None'),
            'token_kind': tk
        }
        self._track_request('POST', self.introspect_endpoint, headers, introspect_data)
        response = self.session.post(self.introspect_endpoint, data=introspect_data, headers=headers)
        self._track_response(response)
        return 'introspect', response

    def authorize_no_pkce(self, **kwargs) -> Tuple[str, requests.Response]:
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': self.config.scope,
            'state': self.state,
            'nonce': self.nonce
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        if response.status_code in (302, 303):
            self.login_form_url = response.headers.get('Location', None)
        else:
            self.login_form_url = response.url or self.login_form_url
        return 'authorize_no_pkce', response

    def authorize_bad_redirect_uri(self, **kwargs) -> Tuple[str, requests.Response]:
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': kwargs.get('redirect_uri', 'http://evil.com/callback'),
            'scope': self.config.scope,
            'state': self.state,
            'nonce': self.nonce,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256'
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        return 'authorize_bad_redirect_uri', response

    def authorize_pkce_s256(self, **kwargs) -> Tuple[str, requests.Response]:
        params = {
            'response_type': 'code',
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
        response = self.session.get(url, allow_redirects=True)
        self._track_response(response)
        return 'authorize_pkce_s256', response

    def authorize_pkce_plain(self, **kwargs) -> Tuple[str, requests.Response]:
        bad_challenge = self.code_verifier
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope': kwargs.get('scope', self.config.scope),
            'state': self.state,
            'nonce': self.nonce,
            'code_challenge': bad_challenge,
            'code_challenge_method': 'S256'
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)
        return 'authorize_pkce_plain', response

    def device_authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        data = {
            'client_id': self.config.client_id,
            'scope': kwargs.get('scope', self.config.scope)
        }
        if self.config.client_secret:
            data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        self._track_request('POST', self.device_authorize_endpoint, headers, data)
        response = self.session.post(self.device_authorize_endpoint, data=data, headers=headers)
        self._track_response(response)
        return 'device_authorize', response

    def logout(self, **kwargs) -> Tuple[str, requests.Response]:
        revoke_data = {'client_id': self.config.client_id}
        if self.config.client_secret:
            revoke_data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        self._track_request('POST', self.revoke_endpoint, headers, revoke_data)
        response = self.session.post(self.revoke_endpoint, data=revoke_data)
        self._track_response(response)
        return 'logout', response

    def token_bad_code(self, **kwargs) -> Tuple[str, requests.Response]:
        token_data = {
            'grant_type': 'authorization_code',
            'code': kwargs.get('code', 'invalid_code_12345'),
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'code_verifier': self.code_verifier
        }
        if self.config.client_secret:
            token_data['client_secret'] = self.config.client_secret
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        self._track_request('POST', self.token_endpoint, headers, token_data)
        response = self.session.post(self.token_endpoint, data=token_data)
        self._track_response(response)
        return 'token_bad_code', response

    def token_wrong_client_secret(self, **kwargs) -> Tuple[str, requests.Response]:
        token_data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'code_verifier': self.code_verifier,
            'client_secret': kwargs.get('client_secret', 'wrong_secret_12345')
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        isolated_session = requests.Session()
        self._track_request('POST', self.token_endpoint, headers, token_data)
        response = isolated_session.post(self.token_endpoint, data=token_data, headers=headers)
        self._track_response(response)
        return 'token_wrong_client_secret', response

    def userinfo_wrong_token(self, **kwargs) -> Tuple[str, requests.Response]:
        headers = {'Authorization': f"Bearer {kwargs.get('token', 'invalid_token_12345')}"}
        isolated_session = requests.Session()
        self._track_request('GET', self.userinfo_endpoint, headers)
        response = isolated_session.get(self.userinfo_endpoint, headers=headers)
        self._track_response(response)
        return 'userinfo_wrong_token', response

    def client_credentials(self, **kwargs) -> Tuple[str, requests.Response]:
        data = {'grant_type': 'client_credentials', 'client_id': self.config.client_id}
        if 'scope' in kwargs:
            data['scope'] = kwargs['scope']
        client_auth = kwargs.get('client_auth', 'post')
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if self.config.client_secret and client_auth == 'basic':
            sec = kwargs.get('client_secret', self.config.client_secret) or ''
            basic = base64.b64encode(f"{self.config.client_id}:{sec}".encode()).decode()
            headers['Authorization'] = f"Basic {basic}"
        elif self.config.client_secret:
            data['client_secret'] = kwargs.get('client_secret', self.config.client_secret)
        self._track_request('POST', self.token_endpoint, headers, data)
        response = self.session.post(self.token_endpoint, data=data, headers=headers)
        self._track_response(response)
        if response.status_code == 200:
            try:
                tj = response.json()
                self.access_token = tj.get('access_token')
                self.refresh_token_value = tj.get('refresh_token')
                self.id_token = tj.get('id_token')
            except:
                pass
        return 'client_credentials', response

    # ── OIDC Discovery (consolidated from GenericOIDCMixin) ─────

    def _discover_endpoints(self, discovery_url: str) -> Optional[Dict]:
        """Fetch and parse the OIDC discovery document."""
        try:
            r = requests.get(discovery_url, timeout=5,
                             headers={'Accept': 'application/json'},
                             verify=False)
            if r.status_code == 200:
                data = r.json()
                if 'authorization_endpoint' in data and 'token_endpoint' in data:
                    print(f"[OIDC Discovery] ✓ {discovery_url}")
                    return data
        except Exception as e:
            print(f"[OIDC Discovery] fallback (reason: {e})")
        return None

    def _apply_discovered_endpoints(self, endpoints: Dict):
        """Populate endpoint attributes from a discovery document."""
        self.auth_endpoint       = endpoints.get('authorization_endpoint')
        self.token_endpoint      = endpoints.get('token_endpoint')
        self.userinfo_endpoint   = endpoints.get('userinfo_endpoint')
        self.introspect_endpoint = endpoints.get('introspection_endpoint')
        self.revoke_endpoint     = endpoints.get('revocation_endpoint')
        self.jwks_endpoint       = endpoints.get('jwks_uri')
        self.device_authorize_endpoint = endpoints.get('device_authorization_endpoint')
        self.registration_endpoint = endpoints.get('registration_endpoint')
        self.end_session_endpoint = endpoints.get('end_session_endpoint')
        self.par_endpoint = endpoints.get('pushed_authorization_request_endpoint')

    def _set_endpoint_defaults(self):
        """Set optional endpoint attributes to None if not already set."""
        for attr in ('device_authorize_endpoint', 'registration_endpoint',
                     'end_session_endpoint', 'par_endpoint'):
            if not hasattr(self, attr):
                setattr(self, attr, None)

    # ── Shared consent detection & auto-approval ──────────────────

    def _looks_like_consent_page(self, body: str) -> bool:
        """Detect Spring AS / CXF / WSO2 consent templates by
        stable markers in the rendered HTML."""
        if not body:
            return False
        markers = (
            # Spring Authorization Server
            'OAuth2ConsentForm',
            'oauth2/authorize',
            'name="scope"',
            'consent_action',
            'Consent required',
            'Authorize ',
            'approve_access',
            # Apache CXF rs-security-oauth2 default OAuthAuthorizationData view
            'oauthDecision',
            'OAuthAuthorizationData',
            'session_authenticity_token',
            'authenticityToken',
            'allow',
            'client_id',
        )
        body_l = body.lower()
        hits = sum(1 for m in markers if m.lower() in body_l)
        return hits >= 2 and (
            'consent' in body_l
            or 'scope' in body_l
            or 'oauthdecision' in body_l
            or 'authoriz' in body_l
        )

    def _post_consent_form(self, page: requests.Response, page_url: str) -> Optional[requests.Response]:
        """Submit the consent form with all offered scopes approved.

        Handles both Spring AS (POST back to /oauth2/authorize with all
        hidden fields + scope checkboxes) and CXF (POST back to the
        service-decision URL with `oauthDecision=allow` plus
        `session_authenticity_token`)."""
        body = page.text or ''
        # Extract CSRF via Spring Security helper
        csrf_name, csrf_val = self._extract_spring_security_csrf(body)
        form_data: Dict[str, list] = {}

        # Hidden + state stats with simple value='...' pairs
        for name, val in re.findall(
                r'<input[^>]+name=["\']([^"\']+)["\'][^>]+value=["\']([^"\']*)["\']',
                body, flags=re.IGNORECASE):
            form_data.setdefault(name, []).append(html.unescape(val))

        if csrf_name and csrf_val and csrf_name not in form_data:
            form_data[csrf_name] = [csrf_val]

        # CXF-specific: oauthDecision radio
        body_l = body.lower()
        if 'oauthdecision' in body_l and 'oauthDecision' not in form_data:
            form_data['oauthDecision'] = ['allow']

        # Derive action URL
        m_action = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if m_action:
            action = html.unescape(m_action.group(1))
            if action.startswith('http'):
                post_url = action
            else:
                post_url = self.config.base_url.rstrip('/') + (
                    action if action.startswith('/') else '/' + action)
        else:
            post_url = page_url

        # Flatten lists for requests: scope=openid&scope=profile&...
        flat: list = []
        for k, vs in form_data.items():
            for v in vs:
                flat.append((k, v))

        try:
            return self.session.post(post_url, data=flat,
                                     allow_redirects=False, timeout=10)
        except Exception:
            return None

    def _auto_approve_consent(self, consent_url: str) -> Optional[requests.Response]:
        """Auto-approve OAuth consent page (Spring AS uses POST with scope checkboxes)."""
        try:
            page = self.session.get(consent_url, allow_redirects=False, timeout=10)
            form_data = {}
            for name, val in re.findall(
                    r'<input[^>]+name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']',
                    page.text or ''):
                form_data[name] = val
            form_data['submit'] = 'Submit Consent'
            post_url = self._derive_login_post_url(page, consent_url)
            return self.session.post(post_url, data=form_data,
                                     allow_redirects=False, timeout=10)
        except Exception:
            return None

    # ── Shared form helpers ───────────────────────────────────────

    def _extract_hidden_fields(self, html_body: str) -> Dict[str, str]:
        """Extract all <input type='hidden'> name/value pairs from HTML.

        Critical for CAS 6.x login forms which require `execution` and
        `_eventId` alongside `_csrf`.  Also works for Spring Security
        (only _csrf) and WSO2 (_csrfToken).

        If _csrf is not found in hidden inputs, also checks <meta> tags
        (CAS 6.x sometimes embeds CSRF in <meta name="_csrf" content="...">).
        """
        if not html_body:
            return {}
        fields = {}
        for m in re.finditer(
                r'<input[^>]+type=["\']hidden["\'][^>]*>'
                r'|<input[^>]+value=["\'][^"\']*["\'][^>]+type=["\']hidden["\'][^>]*>',
                html_body, re.IGNORECASE):
            tag = m.group(0)
            name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.IGNORECASE)
            val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                fields[name_m.group(1)] = html.unescape(val_m.group(1)) if val_m else ''
        # CAS-specific: if _eventId hidden field is missing but the form
        # has a submit button with name="_eventId_submit", add it.
        if '_eventId' not in fields and '_eventId_submit' not in fields:
            if re.search(r'name=["\']_eventId', html_body, re.IGNORECASE):
                fields['_eventId'] = 'submit'
        # Fallback: _csrf may be in a <meta> tag instead of hidden input
        if '_csrf' not in fields:
            csrf_meta = re.search(
                r'<meta[^>]+name=["\']_csrf["\'][^>]+content=["\']([^"\']+)["\']',
                html_body, re.IGNORECASE)
            if csrf_meta:
                fields['_csrf'] = html.unescape(csrf_meta.group(1))
        return fields

    def _derive_login_post_url(self, page: requests.Response, fallback: str) -> str:
        """Extract <form action=...> and resolve against the rendered page URL.

        Spring Security and WSO2 emit absolute-path actions (`action="/login"`)
        which urljoin also handles correctly.
        """
        m = re.search(
            r'<form[^>]+action=["\']([^"\']*)["\']',
            page.text or '', re.IGNORECASE)
        page_url = getattr(page, 'url', '') or fallback
        if not m:
            return fallback
        action = html.unescape(m.group(1))
        if not action:
            return page_url
        if action.startswith('http'):
            resolved = action
        else:
            resolved = urllib.parse.urljoin(page_url, action)

        # Re-inject `service=<raw>` verbatim if urljoin dropped it.
        page_query = urllib.parse.urlparse(page_url).query
        resolved_parsed = urllib.parse.urlparse(resolved)
        resolved_query = resolved_parsed.query

        def _has_key(qs: str, key: str) -> bool:
            return bool(re.search(r'(?:^|&)' + re.escape(key) + r'=', qs))

        def _extract_raw_pair(qs: str, key: str):
            mm = re.search(r'(?:^|&)(' + re.escape(key) + r'=[^&]*)', qs)
            return mm.group(1) if mm else None

        if _has_key(page_query, 'service') and not _has_key(resolved_query, 'service'):
            raw = _extract_raw_pair(page_query, 'service')
            if raw:
                new_query = (resolved_query + '&' + raw) if resolved_query else raw
                resolved = urllib.parse.urlunparse(
                    resolved_parsed._replace(query=new_query))
        return resolved

    def _extract_spring_security_csrf(self, body: str) -> Tuple[Optional[str], Optional[str]]:
        """Extract Spring Security CSRF token from HTML body.

        Returns (field_name, field_value) tuple. Returns (None, None) if
        no CSRF token is found.

        Checks both hidden <input> fields and <meta> tags.
        """
        if not body:
            return None, None
        # Hidden input: <input type="hidden" name="_csrf" value="...">
        for csrf_name in ('_csrf', '_csrf_token', 'csrf_token'):
            m = re.search(
                r'<input[^>]+name=["\']' + re.escape(csrf_name) + r'["\'][^>]+value=["\']([^"\']+)["\']' 
                r'|<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']' + re.escape(csrf_name) + r'["\']',
                body, re.IGNORECASE)
            if m:
                val = m.group(1) or m.group(2)
                return csrf_name, html.unescape(val) if val else None
        # Meta tag: <meta name="_csrf" content="...">
        csrf_meta = re.search(
            r'<meta[^>]+name=["\']_csrf["\'][^>]+content=["\']([^"\']+)["\']',
            body, re.IGNORECASE)
        if csrf_meta:
            return '_csrf', html.unescape(csrf_meta.group(1))
        return None, None

    # ── Small utility shims ───────────────────────────────────────

    def _synthetic_response(self, status: int, text: str) -> requests.Response:
        r = requests.Response()
        r.status_code = status
        r._content = (text or '').encode('utf-8')
        return r

    def _record_sent(self, url: str, method: str, body=None):
        self.sent_data.append({'url': url, 'method': method, 'body': body})

    def _record_received(self, response: requests.Response):
        self.received_data.append({
            'status_code': response.status_code,
            'headers': dict(response.headers),
            'body': (response.text or '')[:2048],
        })

    def get_sent_data(self) -> List[Dict]:
        return self.sent_data.copy()

    def get_received_data(self) -> List[Dict]:
        return self.received_data.copy()

    def get_raw_sent_bytes(self) -> bytes:
        raw_bytes = b''
        for req in self.sent_data:
            method = req['method'].encode()
            url = req['url'].encode()
            headers = b'\r\n'.join(f"{k}: {v}".encode() for k, v in req['headers'].items())
            data = req['data'] if req['data'] else b''
            if isinstance(data, dict):
                data = urllib.parse.urlencode(data).encode()
            raw_bytes += method + b' ' + url + b' HTTP/1.1\r\n'
            raw_bytes += headers + b'\r\n\r\n'
            raw_bytes += data
        return raw_bytes

    def get_raw_received_bytes(self) -> bytes:
        raw_bytes = b''
        for resp in self.received_data:
            status_line = f"HTTP/1.1 {resp['status_code']} OK\r\n".encode()
            headers = b'\r\n'.join(f"{k}: {v}".encode() for k, v in resp['headers'].items())
            raw_bytes += status_line
            raw_bytes += headers + b'\r\n\r\n'
        return raw_bytes