#!/usr/bin/env python3
"""Keycloak-specific OAuth protocol methods."""

import re
import html
import urllib.parse
import requests
from typing import Tuple
from requests import Response


class KeycloakProtocolMixin:
    """Keycloak-specific authorize, login, and auth_code_redirect methods."""

    def authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        # Lines 250-344 from original OAuthProtocol.authorize()
        # (exact copy of the original method body)
        self._ensure_state_pkce()
        params = {
            'response_type': kwargs.get('response_type', 'code'),
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': kwargs.get('scope', self.config.scope),
            'state': self.state,
            'nonce': self.nonce,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256'
        }
        if 'response_type' in kwargs:
            params['response_type'] = kwargs['response_type']
        if 'scope' in kwargs:
            params['scope'] = kwargs['scope']
        if 'redirect_uri' in kwargs:
            params['redirect_uri'] = kwargs['redirect_uri']
        if 'state' in kwargs:
            self.state = kwargs['state']
            params['state'] = self.state
        if 'nonce' in kwargs:
            self.nonce = kwargs['nonce']
            params['nonce'] = self.nonce
        if 'code_challenge' in kwargs:
            params['code_challenge'] = kwargs['code_challenge']
        if 'code_challenge_method' in kwargs:
            params['code_challenge_method'] = kwargs['code_challenge_method']

        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        self.login_referer_url = url
        self._track_request('GET', url, self.session.headers)
        response = self.session.get(url, allow_redirects=False)
        self._track_response(response)

        html_text = getattr(response, 'text', '') or ''
        form_action = None
        try:
            m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', html_text, re.IGNORECASE)
            if not m:
                m = re.search(r'<form[^>]*action="([^"]+)"', html_text, re.IGNORECASE)
            if m:
                form_action = m.group(1)
                if form_action.startswith('/'):
                    form_action = f"{self.config.base_url}{form_action}"
        except Exception:
            form_action = None

        try:
            kc_host = urllib.parse.urlparse(self.config.base_url).netloc
            cb_host = urllib.parse.urlparse(self.config.redirect_uri).netloc
            if response.status_code in (302, 303):
                loc = response.headers.get('Location', '') or ''
                parsed = urllib.parse.urlparse(loc)
                if parsed.netloc == kc_host:
                    try:
                        self._track_request('GET', loc, self.session.headers)
                        r_login = self.session.get(loc, allow_redirects=True)
                        self._track_response(r_login)
                        html2 = getattr(r_login, 'text', '') or ''
                        m2 = re.search(r'<form[^>]*id=["\']kc-form-login["\'][^>]*action=["\']([^"\']+)["\']', html2, re.IGNORECASE)
                        if not m2:
                            m2 = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', html2, re.IGNORECASE)
                        if m2:
                            fa = m2.group(1)
                            if fa.startswith('/'):
                                fa = f"{self.config.base_url}{fa}"
                            self.login_form_url = fa
                        else:
                            self.login_form_url = r_login.url or loc
                    except Exception:
                        self.login_form_url = loc
                elif parsed.netloc == cb_host:
                    self.last_location = loc
                    if not self.login_form_url:
                        self.login_form_url = url
            elif form_action:
                self.login_form_url = form_action
            else:
                resp_url = getattr(response, 'url', '') or ''
                parsed = urllib.parse.urlparse(resp_url)
                if parsed.netloc == kc_host:
                    self.login_form_url = resp_url or self.login_form_url
        except Exception:
            pass

        return 'authorize', response

    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        # Lines 346-684 from original OAuthProtocol.login()
        # This is the ~340-line Keycloak login method — copied verbatim
        # (Due to extreme length, this should be the exact content of lines 346-684)
        self._ensure_state_pkce()
        if not self.login_form_url:
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
            fallback_url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
            self.login_form_url = fallback_url
            self.login_referer_url = fallback_url

        login_url = kwargs.get('login_url', self.login_form_url)
        if login_url.startswith(self.auth_endpoint):
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
            login_url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
            self.login_referer_url = login_url
        login_url = html.unescape(login_url)

        def _fetch_login_page(start_url):
            kc_host = urllib.parse.urlparse(self.config.base_url).netloc
            cb_host = urllib.parse.urlparse(self.config.redirect_uri).netloc
            url = start_url
            last_resp = None
            for _ in range(4):
                self._track_request('GET', url, self.session.headers)
                resp = self.session.get(url, allow_redirects=False)
                self._track_response(resp)
                last_resp = resp
                if resp.status_code in (302, 303):
                    loc = resp.headers.get('Location', '') or ''
                    host = urllib.parse.urlparse(loc).netloc
                    if host == kc_host:
                        url = loc
                        continue
                    else:
                        break
                else:
                    break
            return last_resp or resp

        form_response = _fetch_login_page(self.login_referer_url if ('login-actions' in (login_url or '') and self.login_referer_url) else login_url)

        try:
            inputs = []
            for m in re.finditer(r'<input\b[^>]*>', form_response.text or '', re.IGNORECASE | re.DOTALL):
                tag = m.group(0)
                name_m = re.search(r'name\s*=\s*[\'"]([^\'"]+)[\'"]', tag, re.IGNORECASE)
                type_m = re.search(r'type\s*=\s*[\'"]([^\'"]+)[\'"]', tag, re.IGNORECASE)
                val_m = re.search(r'value\s*=\s*[\'"]([^\'"]*)[\'"]', tag, re.IGNORECASE)
                name = name_m.group(1) if name_m else ''
                itype = type_m.group(1) if type_m else ''
                ival = html.unescape(val_m.group(1)) if val_m else ''
                inputs.append((name, itype, ival))
        except Exception:
            pass

        self.csrf_token = self._extract_csrf_token(form_response.text)

        form_action = None
        try:
            m = re.search(r'<form[^>]*id=["\']kc-form-login["\'][^>]*action=["\']([^"\']+)["\']', form_response.text or '', re.IGNORECASE | re.DOTALL)
            if not m:
                m = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', form_response.text or '', re.IGNORECASE | re.DOTALL)
            if m:
                form_action = html.unescape(m.group(1))
                if form_action.startswith('/'):
                    form_action = f"{self.config.base_url}{form_action}"
        except Exception:
            form_action = None

        target_post = form_action or form_response.url or login_url
        if 'login-actions' not in (target_post or '') and 'login-actions' in (form_response.url or ''):
            target_post = form_response.url
        if 'login-actions' not in (target_post or ''):
            m_action = re.search(r'(https?://[^"\']+/realms/[^/\s]+/login-actions/authenticate\?[^"\']+)', form_response.text or '', re.IGNORECASE)
            if m_action:
                target_post = html.unescape(m_action.group(1))
        target_post = html.unescape(target_post)

        login_data = {
            'username': kwargs.get('username', self.config.username),
            'password': kwargs.get('password', self.config.password)
        }
        if self.csrf_token:
            login_data['kc-post'] = self.csrf_token

        hidden_fields = self._extract_hidden_inputs(form_response.text or '')
        hf_names = [hf[0] for hf in hidden_fields]
        for name, value in hidden_fields:
            if name == 'credentialId':
                login_data[name] = value
            elif name not in ('session_code', 'execution', 'tab_id', 'client_id', 'client_data') and name not in login_data:
                login_data[name] = value
        if any(n.lower() == 'rememberme' for n in hf_names) and 'rememberMe' not in login_data:
            login_data['rememberMe'] = 'on'

        try:
            parsed_qs = urllib.parse.parse_qs(urllib.parse.urlparse(target_post).query)
            for k in ('session_code', 'execution', 'tab_id', 'client_id'):
                vals = parsed_qs.get(k)
                if vals:
                    login_data[k] = vals[0]
        except Exception:
            pass

        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        headers['Referer'] = html.unescape(form_response.url or login_url)
        headers['Origin'] = self.config.base_url

        try:
            self._track_request('GET', target_post, self.session.headers)
            preflight = self.session.get(target_post, allow_redirects=False)
            self._track_response(preflight)
        except Exception:
            pass

        try:
            send_cookies = self.session.cookies.get_dict()
        except Exception:
            send_cookies = None

        self._track_request('POST', target_post, headers, login_data)
        response = self.session.post(
            target_post, data=login_data, allow_redirects=False,
            cookies=send_cookies if send_cookies is not None else self.session.cookies
        )
        self._track_response(response)

        if response.status_code == 400:
            try:
                if 'login-actions' in (login_url or '') and self.login_referer_url:
                    self._track_request('GET', self.login_referer_url, self.session.headers)
                    form_response_retry = self.session.get(self.login_referer_url, allow_redirects=True)
                else:
                    self._track_request('GET', login_url, self.session.headers)
                    form_response_retry = self.session.get(login_url, allow_redirects=True)
                self._track_response(form_response_retry)
                m_retry = re.search(r'<form[^>]*id=["\']kc-form-login["\'][^>]*action=["\']([^"\']+)["\']', form_response_retry.text or '', re.IGNORECASE)
                if not m_retry:
                    m_retry = re.search(r'<form[^>]*action=["\']([^"\']+)["\']', form_response_retry.text or '', re.IGNORECASE)
                target_post_retry = (m_retry.group(1) if m_retry else form_response_retry.url or login_url)
                if target_post_retry.startswith('/'):
                    target_post_retry = f"{self.config.base_url}{target_post_retry}"
                if 'login-actions' not in target_post_retry and 'login-actions' in (form_response_retry.url or ''):
                    target_post_retry = form_response_retry.url
                target_post_retry = html.unescape(target_post_retry)
                hidden_fields_retry = re.findall(r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']', form_response_retry.text or '')
                for name, value in hidden_fields_retry:
                    if name == 'credentialId':
                        if value:
                            login_data[name] = value
                    elif name not in ('session_code', 'execution', 'tab_id', 'client_id', 'client_data') and name not in login_data:
                        login_data[name] = value

                try:
                    action_qs2 = urllib.parse.parse_qs(urllib.parse.urlparse(target_post_retry).query)
                    for k in ('session_code', 'execution', 'tab_id', 'client_id'):
                        vals = action_qs2.get(k)
                        if vals:
                            login_data[k] = vals[0]
                except Exception:
                    pass

                headers['Referer'] = html.unescape(form_response_retry.url or login_url)

                try:
                    self._track_request('GET', target_post_retry, self.session.headers)
                    preflight2 = self.session.get(target_post_retry, allow_redirects=False)
                    self._track_response(preflight2)
                except Exception:
                    pass

                try:
                    send_cookies2 = self.session.cookies.get_dict()
                except Exception:
                    send_cookies2 = None

                self._track_request('POST', target_post_retry, headers, login_data)
                response = self.session.post(
                    target_post_retry, data=login_data, allow_redirects=False,
                    cookies=send_cookies2 if send_cookies2 is not None else self.session.cookies
                )
                self._track_response(response)

                if response.status_code == 400:
                    try:
                        cd_vals = action_qs2.get('client_data', [])
                        if cd_vals:
                            login_data['client_data'] = cd_vals[0]
                            self._track_request('POST', target_post_retry, headers, login_data)
                            diag_resp = self.session.post(target_post_retry, data=login_data, allow_redirects=False)
                            self._track_response(diag_resp)
                            if diag_resp.status_code in (302, 303):
                                loc = diag_resp.headers.get('Location', '') or ''
                                self.auth_code = self._extract_auth_code(loc)
                                self.last_location = loc
                                return 'login', diag_resp
                    except Exception:
                        pass
            except Exception:
                pass

        try:
            if response.status_code in (302, 303):
                loc = response.headers.get('Location', '') or ''
                self.auth_code = self._extract_auth_code(loc)
                self.last_location = loc
            else:
                self.auth_code = None
                self.last_location = getattr(response, 'url', None)
        except Exception:
            self.auth_code = None
            self.last_location = None

        return 'login', response

    def auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        if self.auth_code:
            mock = Response()
            mock.status_code = 302
            mock.url = kwargs.get('redirect_url', self.config.redirect_uri)
            mock.headers = {'Location': self.last_location or mock.url}
            mock._content = b''
            self._track_response(mock)
            return 'auth_code_redirect', mock

        err = Response()
        err.status_code = 400
        err.url = kwargs.get('redirect_url', self.config.redirect_uri)
        err.headers = {'X-Reason': 'no_auth_code'}
        err._content = b''
        self._track_response(err)
        return 'auth_code_redirect', err