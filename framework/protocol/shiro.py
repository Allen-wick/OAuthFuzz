#!/usr/bin/env python3
"""
Apache Shiro OAuth 2.0 Protocol Mixin

Custom OAuth2 server built on Apache Shiro 2.2.0 security framework.
Provides:
  - Standard RFC 6749 authorization_code + PKCE flow
  - OIDC discovery at /.well-known/openid-configuration (optional)
  - Shiro-based form login at /login
  - Token introspection, revocation, UserInfo endpoints
"""

import urllib.parse
import requests
from typing import Tuple, Optional

from protocol.base import OAuthProtocolBase


class ShiroProtocolMixin(OAuthProtocolBase):
    """Apache Shiro OAuth 2.0 protocol mixin."""

    # ── Endpoint configuration ────────────────────────────────────

    def _configure_endpoints(self):
        base = self.config.base_url.rstrip('/')
        discovery_url = f"{base}/.well-known/openid-configuration"

        endpoints = self._discover_endpoints(discovery_url)
        if endpoints:
            self._apply_discovered_endpoints(endpoints)
            return

        # Fallback: conventional Shiro OAuth2 paths
        self.auth_endpoint       = f"{base}/oauth2/authorize"
        self.token_endpoint      = f"{base}/oauth2/token"
        self.userinfo_endpoint   = f"{base}/oauth2/userinfo"
        self.introspect_endpoint = f"{base}/oauth2/introspect"
        self.revoke_endpoint     = f"{base}/oauth2/revoke"
        self.jwks_endpoint       = f"{base}/oauth2/jwks"
        self._set_endpoint_defaults()

    # ── authorize ──────────────────────────────────────────────────

    def authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        """Standard RFC 6749 authorization_code + PKCE flow."""
        self._ensure_state_pkce()

        params = {
            'response_type': kwargs.get('response_type', 'code'),
            'client_id':     kwargs.get('client_id', self.config.client_id),
            'redirect_uri':  kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope':         kwargs.get('scope', self.config.scope),
            'state':         kwargs.get('state', self.state),
            'nonce':         kwargs.get('nonce', self.nonce),
            'code_challenge': kwargs.get('code_challenge', self.code_challenge),
            'code_challenge_method': kwargs.get('code_challenge_method', 'S256'),
        }

        url = f"{self.auth_endpoint}?{urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})}"
        try:
            r = self.session.get(url, allow_redirects=False, timeout=10)
            self._record_sent(url, 'GET')
            self._record_received(r)
            self.last_location = r.headers.get('Location', '')
            self._authorize_url = url
            self._authorize_response = r

            # Populate login_form_url if redirect points to /login
            if self.last_location and '/login' in self.last_location.lower():
                base = self.config.base_url.rstrip('/')
                self.login_form_url = (
                    self.last_location if self.last_location.startswith('http')
                    else base + self.last_location)

            # Direct-approve path: the 302 Location already carries ?code=…
            if self.last_location and 'code=' in self.last_location:
                try:
                    q = urllib.parse.urlparse(self.last_location).query
                    qp = urllib.parse.parse_qs(q)
                    if 'code' in qp:
                        self.auth_code = qp['code'][0]
                except Exception:
                    pass
            return 'authorize', r
        except Exception as e:
            return 'authorize_error', self._synthetic_response(500, str(e))

    # ── login ──────────────────────────────────────────────────────

    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        """Shiro-based HTML form login."""
        base = self.config.base_url.rstrip('/')
        login_page_url = (
            self.login_form_url
            or (self.last_location if getattr(self, 'last_location', '') else None)
            or f"{base}/login"
        )
        if login_page_url and login_page_url.startswith('/'):
            login_page_url = base + login_page_url
        try:
            page = self.session.get(login_page_url, allow_redirects=True, timeout=10)
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

        hidden_fields = self._extract_hidden_fields(page.text)

        form_data = {
            'username': kwargs.get('username', self.config.username),
            'password': kwargs.get('password', self.config.password),
        }
        form_data.update(hidden_fields)

        login_post_url = self._derive_login_post_url(page, login_page_url)
        try:
            r = self.session.post(login_post_url, data=form_data,
                                  allow_redirects=False, timeout=10)
            self._record_sent(login_post_url, 'POST', form_data)
            self._record_received(r)
            loc = r.headers.get('Location', '')
            if loc and not loc.startswith('http'):
                loc = urllib.parse.urljoin(login_post_url, loc)
            self.last_location = loc
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

        return 'login', r

    # ── auth_code_redirect ─────────────────────────────────────────

    def auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Follow redirect chain to extract auth code from callback URL.

        Handles Shiro OAuth2 redirect shapes:
          1. Direct 302 to redirect_uri?code=...
          2. Code already extracted by authorize()
          3. 200 HTML consent page (if implemented)
        """
        # Shape 2 — code already extracted by authorize()
        if self.auth_code and self.last_location and 'code=' in self.last_location:
            return 'auth_code_direct', (
                self._authorize_response
                if getattr(self, '_authorize_response', None) is not None
                else self._synthetic_response(200, 'code extracted from previous step')
            )

        if not self.last_location:
            return 'no_redirect', self._synthetic_response(400, 'no prior authorize redirect')

        # Resolve relative last_location
        target = self.last_location
        if target and not target.startswith('http'):
            target = self.config.base_url.rstrip('/') + (
                target if target.startswith('/') else '/' + target)

        for _ in range(8):
            try:
                r = self.session.get(target, allow_redirects=False, timeout=10)
            except Exception as e:
                return 'redirect_error', self._synthetic_response(500, str(e))

            loc = r.headers.get('Location', '')
            status = r.status_code

            # 1) Direct callback with ?code=…
            if loc and 'code=' in loc:
                q = urllib.parse.urlparse(loc).query
                params = urllib.parse.parse_qs(q)
                if 'code' in params:
                    self.auth_code = params['code'][0]
                self.last_location = loc
                self._record_received(r)
                return 'auth_code', r

            # 3) 200-HTML consent page (if Shiro implements consent)
            if status == 200 and self._looks_like_consent_page(r.text or ''):
                consent_r = self._post_consent_form(r, target)
                if consent_r is not None:
                    post_loc = consent_r.headers.get('Location', '')
                    if 'code=' in post_loc:
                        q = urllib.parse.urlparse(post_loc).query
                        params = urllib.parse.parse_qs(q)
                        if 'code' in params:
                            self.auth_code = params['code'][0]
                        self.last_location = post_loc
                        self._record_received(consent_r)
                        return 'auth_code_after_consent', consent_r
                    if post_loc:
                        target = post_loc if post_loc.startswith('http') else (
                            self.config.base_url.rstrip('/') + post_loc)
                        self.last_location = target
                        continue

            # No more redirects
            if not loc or status not in (301, 302, 303, 307, 308):
                self._record_received(r)
                return 'auth_code_final', r

            target = loc if loc.startswith('http') else (
                self.config.base_url.rstrip('/') + loc)
            self.last_location = target

        return 'redirect_exhausted', self._synthetic_response(400, 'redirect chain too deep')
