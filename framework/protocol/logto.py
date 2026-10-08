#!/usr/bin/env python3
"""
Logto Protocol Mixin

Logto is a Node.js-based OIDC provider (built on oidc-provider by Panva).
Key Logto-specific behaviors:
  - OIDC discovery at /oidc/.well-known/openid-configuration
  - Standard authorization_code + PKCE flow
  - React SPA login via Interaction API (/api/experience/*)
  - PAR not implemented
  - Endpoints mounted under /oidc/ prefix
"""

import urllib.parse
import requests
from typing import Tuple, Optional

from protocol.base import OAuthProtocolBase


class LogtoProtocolMixin(OAuthProtocolBase):
    """Logto OIDC protocol mixin."""

    # ── Endpoint configuration ────────────────────────────────────

    def _configure_endpoints(self):
        base = self.config.base_url.rstrip('/')
        discovery_url = f"{base}/oidc/.well-known/openid-configuration"

        endpoints = self._discover_endpoints(discovery_url)
        if endpoints:
            self._apply_discovered_endpoints(endpoints)
            return

        # Fallback: conventional Logto paths
        self.auth_endpoint       = f"{base}/oidc/auth"
        self.token_endpoint      = f"{base}/oidc/token"
        self.userinfo_endpoint   = f"{base}/oidc/me"
        self.introspect_endpoint = f"{base}/oidc/token/introspection"
        self.revoke_endpoint     = f"{base}/oidc/token/revocation"
        self.jwks_endpoint       = f"{base}/oidc/jwks"
        self.par_endpoint        = None          # PAR not implemented in Logto
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

            # Populate login_form_url if redirect points to /login or /sign-in
            if self.last_location and ('/login' in self.last_location.lower()
                                       or '/sign-in' in self.last_location.lower()):
                base = self.config.base_url.rstrip('/')
                self.login_form_url = (
                    self.last_location if self.last_location.startswith('http')
                    else base + self.last_location)

            # Direct-approve path
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

    # ── login (Interaction API) ────────────────────────────────────

    def login(self, **kwargs) -> Tuple[str, requests.Response]:
        """Logto SPA sign-in via Interaction API.

        Flow:
          1. PUT  /api/experience → {"interactionEvent":"SignIn"}
          2. POST /api/experience/verification/password → {identifier, password}
          3. POST /api/experience/identification → {verificationId}
          4. POST /api/experience/submit → {}
        """
        base = self.config.base_url.rstrip('/')
        username = kwargs.get('username', self.config.username)
        password = kwargs.get('password', self.config.password)
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

        # Step 1: Initiate SignIn interaction
        try:
            r1 = self.session.put(
                f"{base}/api/experience",
                json={"interactionEvent": "SignIn"},
                headers=headers, allow_redirects=False, timeout=10)
            self._record_sent(f"{base}/api/experience", 'PUT',
                              {"interactionEvent": "SignIn"})
            self._record_received(r1)
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

        # Step 2: Password verification
        try:
            r2 = self.session.post(
                f"{base}/api/experience/verification/password",
                json={
                    "identifier": {"type": "username", "value": username},
                    "password": password,
                },
                headers=headers, allow_redirects=False, timeout=10)
            self._record_sent(f"{base}/api/experience/verification/password",
                              'POST', {"identifier": username, "password": "***"})
            self._record_received(r2)
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

        # Extract verificationId
        verification_id = None
        try:
            body = r2.json()
            verification_id = body.get('verificationId')
        except Exception:
            pass

        if not verification_id:
            return 'login_error', r2

        # Step 3: Identification
        try:
            r3 = self.session.post(
                f"{base}/api/experience/identification",
                json={"verificationId": verification_id},
                headers=headers, allow_redirects=False, timeout=10)
            self._record_sent(f"{base}/api/experience/identification",
                              'POST', {"verificationId": verification_id})
            self._record_received(r3)
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

        # Step 4: Submit interaction
        try:
            r4 = self.session.post(
                f"{base}/api/experience/submit",
                json={},
                headers=headers, allow_redirects=False, timeout=10)
            self._record_sent(f"{base}/api/experience/submit", 'POST', {})
            self._record_received(r4)
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

        # Store redirectTo for auth_code_redirect
        try:
            body = r4.json()
            redirect_to = body.get('redirectTo', '')
            if redirect_to:
                if not redirect_to.startswith('http'):
                    redirect_to = base + redirect_to
                self.last_location = redirect_to
                self._logto_redirect_to = redirect_to
        except Exception:
            pass

        return 'login', r4

    # ── auth_code_redirect ─────────────────────────────────────────

    def auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Follow Logto redirect chain to extract auth code from callback URL.

        After login() completes, follows the redirectTo chain:
          - /consent?app_id=... (may auto-grant via 302, or show consent form)
          - /oidc/auth/{interactionId} → 303 → callback?code=...
        """
        # Code already extracted by authorize()
        if self.auth_code and self.last_location and 'code=' in self.last_location:
            return 'auth_code_direct', (
                self._authorize_response
                if getattr(self, '_authorize_response', None) is not None
                else self._synthetic_response(200, 'code extracted from previous step')
            )

        if not self.last_location:
            saved = getattr(self, '_authorize_response', None)
            saved_url = getattr(self, '_authorize_url', None)
            if (saved is not None and saved.status_code == 200
                    and saved_url is not None
                    and self._looks_like_consent_page(saved.text or '')):
                consent_r = self._post_consent_form(saved, saved_url)
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
                return 'consent_no_code', saved
            return 'no_redirect', self._synthetic_response(400, 'no prior authorize redirect')

        base = self.config.base_url.rstrip('/')
        target = self.last_location
        if target and not target.startswith('http'):
            target = base + (target if target.startswith('/') else '/' + target)

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

            # 2) Consent redirect (302 from /consent — auto-grant)
            if loc and 'consent' in loc.lower():
                # Follow the consent redirect
                consent_url = loc if loc.startswith('http') else base + loc
                try:
                    consent_r = self.session.get(consent_url, allow_redirects=False, timeout=10)
                    self._record_received(consent_r)
                except Exception as e:
                    return 'redirect_error', self._synthetic_response(500, str(e))

                consent_loc = consent_r.headers.get('Location', '')
                consent_status = consent_r.status_code

                # Auto-grant: consent page returns 302
                if consent_loc:
                    if 'code=' in consent_loc:
                        q = urllib.parse.urlparse(consent_loc).query
                        params = urllib.parse.parse_qs(q)
                        if 'code' in params:
                            self.auth_code = params['code'][0]
                        self.last_location = consent_loc
                        return 'auth_code_after_consent', consent_r

                    # Follow intermediate redirect (e.g. /oidc/auth/{id})
                    target = consent_loc if consent_loc.startswith('http') else base + consent_loc
                    self.last_location = target
                    continue

                # Manual consent: consent page returns 200 with form
                if consent_status == 200 and self._looks_like_consent_page(consent_r.text or ''):
                    post_r = self._logto_post_consent(consent_r, consent_url)
                    if post_r is not None:
                        post_loc = post_r.headers.get('Location', '')
                        if 'code=' in post_loc:
                            q = urllib.parse.urlparse(post_loc).query
                            params = urllib.parse.parse_qs(q)
                            if 'code' in params:
                                self.auth_code = params['code'][0]
                            self.last_location = post_loc
                            self._record_received(post_r)
                            return 'auth_code_after_consent', post_r
                        if post_loc:
                            target = post_loc if post_loc.startswith('http') else base + post_loc
                            self.last_location = target
                            continue

                # No more redirects from consent
                self._record_received(consent_r)
                return 'consent_no_code', consent_r

            # 3) 200-HTML consent page at current target
            if status == 200 and self._looks_like_consent_page(r.text or ''):
                consent_r = self._logto_post_consent(r, target)
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
                        target = post_loc if post_loc.startswith('http') else base + post_loc
                        self.last_location = target
                        continue

            # 4) Generic redirect — follow it
            if loc and status in (301, 302, 303, 307, 308):
                target = loc if loc.startswith('http') else base + loc
                self.last_location = target
                continue

            # No more redirects
            self._record_received(r)
            if status == 200 and not self.auth_code:
                try:
                    snippet = (r.text or '')[:200].replace('\n', ' ')
                    print(f"[logto_auth_code_redirect] WARN: chain ended 200 "
                          f"at {target[:200]} with no code. Body: {snippet}")
                except Exception:
                    pass
            return 'auth_code_final', r

        return 'redirect_exhausted', self._synthetic_response(400, 'redirect chain too deep')

    # ── Logto-specific consent POST ────────────────────────────────

    def _logto_post_consent(self, consent_page, consent_url: str):
        """POST /api/interaction/consent for manual consent submission."""
        base = self.config.base_url.rstrip('/')
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        try:
            r = self.session.post(
                f"{base}/api/interaction/consent",
                json={},
                headers=headers,
                allow_redirects=False,
                timeout=10)
            self._record_sent(f"{base}/api/interaction/consent", 'POST', {})
            self._record_received(r)
            return r
        except Exception:
            return None

    # ── Logto-specific attack methods ────────────────────────────────

    def logto_pkce_plain(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test whether Logto accepts code_challenge_method=plain (PKCE downgrade).

        Logto requires PKCE (S256). If plain is accepted, this is a PKCE
        downgrade vulnerability allowing trivial code_verifier prediction.
        """
        self._ensure_state_pkce()
        import hashlib, base64
        # Generate a plain challenge (verbatim value)
        verifier = base64.urlsafe_b64encode(b'logto-test-verifier-12345').rstrip(b'=').decode()
        challenge = verifier  # plain: challenge == verifier

        params = {
            'response_type': 'code',
            'client_id': kwargs.get('client_id', self.config.client_id),
            'redirect_uri': kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope': kwargs.get('scope', self.config.scope),
            'state': kwargs.get('state', self.state),
            'nonce': kwargs.get('nonce', self.nonce),
            'code_challenge': challenge,
            'code_challenge_method': 'plain',
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        try:
            r = self.session.get(url, allow_redirects=False, timeout=10)
            self._record_sent(url, 'GET')
            self._record_received(r)
            self.last_location = r.headers.get('Location', '')
            return 'logto_pkce_plain', r
        except Exception as e:
            return 'logto_pkce_plain_error', self._synthetic_response(500, str(e))

    def logto_code_replay(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test authorization code anti-replay protection.

        Exchanges the same auth code a second time. RFC 6749 §4.1.2 requires
        auth codes be single-use — the second exchange MUST fail.
        """
        if not self.auth_code:
            return 'no_code', self._synthetic_response(400, 'no auth code available for replay test')

        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        }
        try:
            r = self.session.post(self.token_endpoint, data=data, timeout=10, verify=False)
            self._record_sent(self.token_endpoint, 'POST', data)
            self._record_received(r)
            return 'logto_code_replay', r
        except Exception as e:
            return 'logto_code_replay_error', self._synthetic_response(500, str(e))

    def logto_introspect_cross_client(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test cross-client introspection — using different client credentials
        to introspect a token issued to another client.

        RFC 7662 §2.1 permits this, but the response MUST NOT reveal more
        than active/inactive if the caller is not the token's owner.
        """
        token = kwargs.get('token', self.access_token or 'test')
        # Use a different client_id/secret to introspect
        other_client_id = kwargs.get('other_client_id', 'cross-client-test')
        other_client_secret = kwargs.get('other_client_secret', 'cross-client-secret')

        data = {
            'token': token,
            'client_id': other_client_id,
            'client_secret': other_client_secret,
        }
        try:
            r = self.session.post(self.introspect_endpoint, data=data, timeout=10, verify=False)
            self._record_sent(self.introspect_endpoint, 'POST', data)
            self._record_received(r)
            return 'logto_introspect_cross_client', r
        except Exception as e:
            return 'logto_introspect_cross_client_error', self._synthetic_response(500, str(e))

    def logto_scope_escalation(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test scope escalation — request elevated scopes (admin, superuser)
        and verify whether they are actually granted in the token response.
        """
        # Use the standard token exchange but with escalated scopes
        escalated_scope = kwargs.get('scope', 'openid profile email admin superuser root')
        data = {
            'grant_type': 'authorization_code',
            'code': self.auth_code or kwargs.get('code', ''),
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'scope': escalated_scope,
        }
        try:
            r = self.session.post(self.token_endpoint, data=data, timeout=10, verify=False)
            self._record_sent(self.token_endpoint, 'POST', data)
            self._record_received(r)
            return 'logto_scope_escalation', r
        except Exception as e:
            return 'logto_scope_escalation_error', self._synthetic_response(500, str(e))

    def logto_content_type_json(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test Content-Type manipulation at token endpoint.

        Send token exchange with Content-Type: application/json instead of
        application/x-www-form-urlencoded. Some implementations incorrectly
        accept JSON bodies, potentially bypassing validation.
        """
        if not self.auth_code:
            return 'no_code', self._synthetic_response(400, 'no auth code available')

        import json
        body = json.dumps({
            'grant_type': 'authorization_code',
            'code': self.auth_code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
        })
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        try:
            r = self.session.post(self.token_endpoint, data=body,
                                  headers=headers, timeout=10, verify=False)
            self._record_sent(self.token_endpoint, 'POST', body)
            self._record_received(r)
            return 'logto_content_type_json', r
        except Exception as e:
            return 'logto_content_type_json_error', self._synthetic_response(500, str(e))
