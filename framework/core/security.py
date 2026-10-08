#!/usr/bin/env python3
"""Security oracles and race condition testing for OAuth flows."""

import time
import re
import json
import threading
import concurrent.futures
import requests
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from OAuthMapper.OAuthProtocol import OAuthProtocol

class SecurityOracles:
    """Security-focused analysis of OAuth protocol interactions - ENHANCED"""
    
    def __init__(self, oauth_protocol: "OAuthProtocol"):
        self.oauth_protocol = oauth_protocol
        self.findings = []
        
        self.body_vuln_patterns = [
            (r'<script[^>]*>', 'XSS_REFLECTION', 'Potential XSS reflection in response body'),
            (r'sql\s*syntax|mysql|postgres|oracle|sqlite', 'SQL_ERROR_LEAK', 'SQL error message leaked in response'),
            (r'stack\s*trace|traceback|exception\s+in\s+thread', 'STACK_TRACE_LEAK', 'Stack trace leaked in response'),
            (r'java\.lang\.|\.java:\d+', 'JAVA_ERROR_LEAK', 'Java error details leaked'),
            (r'password|secret|private.?key', 'SENSITIVE_DATA_LEAK', 'Potential sensitive data in response'),
            (r'<%|%>|<\?php', 'SERVER_CODE_LEAK', 'Server-side code leaked in response'),
            (r'jdbc|datasource|mysql.*error', 'DATABASE_ERROR_LEAK', 'Database connection details leaked'),
        ]
        
        # FIXED: Improved vulnerability indicators with semantic checks
        self.vuln_indicators = {
            'pkce_not_enforced': {
                'condition': lambda sym, res, seq, ctx: self._check_pkce_bypass(sym, res, seq, ctx),
                'severity': 'HIGH',
                'cwe': 'CWE-287',
                'description': 'PKCE not properly enforced'
            },
            'open_redirect': {
                'condition': lambda sym, res, seq, ctx: self._check_open_redirect(sym, res, seq, ctx),
                'severity': 'HIGH',
                'cwe': 'CWE-601',
                'description': 'Open redirect vulnerability'
            },
            'auth_bypass': {
                'condition': lambda sym, res, seq, ctx: self._check_auth_bypass(sym, res, seq, ctx),
                'severity': 'CRITICAL',
                'cwe': 'CWE-287',
                'description': 'Authentication bypass detected'
            },
            'scope_escalation': {
                'condition': lambda sym, res, seq, ctx: (
                    'ScopeEscalation' in sym and 
                    res == 'Success' and
                    ctx.get('scope_granted') != ctx.get('scope_requested')
                ),
                'severity': 'HIGH',
                'cwe': 'CWE-269',
                'description': 'Scope escalation vulnerability'
            },
            '2fa_bypass': {
                'condition': lambda sym, res, seq, ctx: self._check_2fa_bypass(sym, res, seq, ctx),
                'severity': 'CRITICAL',
                'cwe': 'CWE-308',
                'description': '2FA bypass detected'
            },
            'token_confusion': {
                'condition': lambda sym, res, seq, ctx: (
                    ('UseRefreshAsAccess' in sym or 'UseIDTokenAsAccess' in sym) and
                    res == 'Success' and
                    ctx.get('token_accepted', False)
                ),
                'severity': 'CRITICAL',
                'cwe': 'CWE-287',
                'description': 'Token confusion attack successful'
            },
            'code_replay': {
                'condition': lambda sym, res, seq, ctx: (
                    'TokenExchange' in sym and
                    seq.count('TokenExchange') > 1 and
                    res == 'Success' and
                    ctx.get('is_code_reuse', False)
                ),
                'severity': 'HIGH',
                'cwe': 'CWE-294',
                'description': 'Authorization code replay attack'
            }
        }
    
    def _check_pkce_bypass(self, sym: str, res: str, seq: List[str], ctx: Dict) -> bool:
        """
        FIXED: Properly detect PKCE bypass.
        
        A real PKCE bypass occurs ONLY when:
        1. Authorization request was made without PKCE (code_challenge)
        2. AND token exchange succeeded (not just login page served)
        3. AND access_token was actually issued
        
        NOT a bypass when:
        - Login page is served (HTTP 200 but no code issued)
        - Redirect to login/consent flow
        - Token exchange fails
        """
        if 'AuthorizeNoPKCE' not in sym:
            return False
        
        # Check if this was just login page being served (NOT a bypass)
        response_data = ctx.get('response_data', {})
        status_code = ctx.get('status_code', 0)
        
        # HTTP 200 on authorize endpoint = login page served, NOT auth success
        if status_code == 200:
            response_text = ctx.get('response_text', '')
            if any(indicator in response_text.lower() for indicator in 
                   ['login', 'password', 'username', 'firstfactor', 'sign in', 'authenticate',
                    '<form', '<input', 'type="password"']):
                return False
        
        # Check if authorization code was actually issued
        location = ctx.get('location', '')
        if status_code in (302, 303):
            if 'code=' in location and 'error' not in location.lower():
                if 'TokenExchange' in seq:
                    token_result = ctx.get('token_exchange_result')
                    if token_result == 'Success' and ctx.get('access_token'):
                        return True  # REAL PKCE BYPASS
        
        return False
    
    def _check_open_redirect(self, sym: str, res: str, seq: List[str], ctx: Dict) -> bool:
        """
        FIXED: Properly detect open redirect vulnerabilities.
        
        A real open redirect occurs ONLY when:
        1. Malicious redirect_uri was provided
        2. AND server redirects TO the malicious URI (not to error page)
        
        NOT a vulnerability when:
        - Redirect goes to error page
        - Redirect goes to consent page with error parameter
        - Server returns 400 Bad Request
        """
        if not ('OpenRedirect' in sym or 'BadRedirectUri' in sym):
            return False
        
        if res != 'Redirect':
            return False
        
        location = ctx.get('location', '')
        malicious_uri = ctx.get('malicious_redirect_uri', '')
        
        # Check if redirect actually goes to malicious domain
        malicious_indicators = ['evil.com', 'attacker.com', 'javascript:', 'data:', '//evil']
        
        # Only flag as vulnerability if Location header contains malicious URI
        for indicator in malicious_indicators:
            if indicator in location.lower():
                return True  # REAL OPEN REDIRECT
        
        # If redirect goes to error page, this is DEFENSIVE behavior
        if any(safe in location.lower() for safe in 
               ['error=', 'invalid_redirect', 'redirect_uri', 'api/oidc']):
            return False
        
        return False
    
    def _check_auth_bypass(self, sym: str, res: str, seq: List[str], ctx: Dict) -> bool:
        """
        FIXED: Properly detect authentication bypass.
        
        A real auth bypass occurs ONLY when:
        1. Protected resource accessed without valid authentication
        2. AND server returns actual protected data (not just HTTP 200)
        
        NOT a bypass when:
        - HTTP 200 with error JSON body
        - HTTP 200 with authentication required response
        """
        bypass_symbols = ['FirstFactorBypass', 'AuthBypass', '2FABypass', 'ConsentBypass']
        
        if not any(s in sym for s in bypass_symbols):
            return False
        
        if res != 'Success':
            return False
        
        # Check response content - HTTP 200 doesn't mean bypass
        response_text = ctx.get('response_text', '')
        status_code = ctx.get('status_code', 200)
        
        # Check for error indicators in response body
        error_indicators = [
            '"status":"error"',
            '"authentication"',
            'authentication required',
            'not authenticated',
            'unauthorized',
            '"error":',
            'redirect_uri',  # Consent page asking for redirect_uri
            'consent_id',    # Consent page
        ]
        
        for indicator in error_indicators:
            if indicator.lower() in response_text.lower():
                return False  # Not a bypass, server returned error/auth required
        
        # Check if actual protected data was returned
        success_indicators = [
            'access_token',
            'id_token',
            'refresh_token',
            '"sub":',  # User subject claim
            '"email":',
        ]
        
        for indicator in success_indicators:
            if indicator in response_text:
                return True  # REAL AUTH BYPASS - protected data returned
        
        return False
    
    def _check_2fa_bypass(self, sym: str, res: str, seq: List[str], ctx: Dict) -> bool:
        """Detect 2FA bypass attempts"""
        if '2FA' not in sym.upper() and 'SECONDFACTOR' not in sym.upper():
            return False
        
        # Check if 2FA was skipped but auth still succeeded
        if 'AutheliaSecondFactor' not in seq and res == 'Success':
            # Verify actual token was obtained
            if ctx.get('access_token'):
                return True
        
        return False
    
    def check_sequence(self, sequence: List[str], results: List[str], 
                      contexts: List[Dict] = None) -> List[Dict]:
        """
        Enhanced sequence checking with context awareness.
        """
        self.findings = []
        contexts = contexts or [{}] * len(sequence)
        
        for i, (sym, res) in enumerate(zip(sequence, results)):
            ctx = contexts[i] if i < len(contexts) else {}
            
            for vuln_name, vuln_config in self.vuln_indicators.items():
                try:
                    condition = vuln_config['condition']
                    # Pass full context including sequence position
                    ctx['sequence_position'] = i
                    ctx['full_sequence'] = sequence
                    ctx['results_so_far'] = results[:i+1]
                    
                    if condition(sym, res, sequence, ctx):
                        self.findings.append({
                            'type': vuln_name,
                            'severity': vuln_config['severity'],
                            'cwe': vuln_config.get('cwe', 'N/A'),
                            'description': vuln_config['description'],
                            'symbol': sym,
                            'result': res,
                            'sequence_position': i,
                            'context': {k: v for k, v in ctx.items() 
                                       if k not in ['full_sequence', 'results_so_far']}
                        })
                except Exception as e:
                    pass  # Silently skip failed checks
        
        return self.findings

    def _find_last_response(self, endpoint_substr: str) -> Dict:
        data = list(getattr(self.oauth_protocol, 'received_data', []) or [])
        for resp in reversed(data):
            if endpoint_substr in (resp.get('url') or ''):
                return resp
        return {}

    def _decode_jwt(self, token: Optional[str]) -> Tuple[Dict, Dict]:
        import base64, json
        if not token or token.count('.') < 2:
            return {}, {}
        try:
            h, p, _ = token.split('.', 2)
            def b64d(x):
                x += '=' * (-len(x) % 4)
                return base64.urlsafe_b64decode(x.encode())
            header = json.loads((b64d(h)).decode('utf-8', 'ignore'))
            payload = json.loads((b64d(p)).decode('utf-8', 'ignore'))
            return header, payload
        except Exception:
            return {}, {}

    def rfc_compliance(self, sequence: List[str], results: List[str]) -> List[Dict]:
        findings = []
        for idx, (sym, res) in enumerate(zip(sequence, results)):
            if res == 'ServerError':
                findings.append({'type': 'SERVER_ERROR', 'detail': f'{sym} returned 5xx', 'severity': 'HIGH'})
            if sym == 'UserInfoWrongToken' and res == 'Success':
                resp = self._get_response_at(idx)
                if not self._response_contains_error(resp):
                    findings.append({'type': 'AUTH_BYPASS', 'detail': 'UserInfo with invalid token returned 200 without error', 'severity': 'HIGH'})
            if sym == 'TokenWrongClientSecret' and res == 'Success':
                resp = self._get_response_at(idx)
                if not self._response_contains_error(resp):
                    findings.append({'type': 'CLIENT_AUTH_BYPASS', 'detail': 'Token endpoint accepted wrong client_secret', 'severity': 'HIGH'})
            if sym == 'TokenBadCode' and res == 'Success':
                resp = self._get_response_at(idx)
                if not self._response_contains_error(resp):
                    findings.append({'type': 'CODE_VALIDATION_BYPASS', 'detail': 'Token endpoint accepted bad code', 'severity': 'HIGH'})
            # NEW: Implicit flow should be rejected
            if sym == 'AuthorizeImplicit' and res == 'Success':
                findings.append({'type': 'IMPLICIT_FLOW_ALLOWED', 'detail': 'Implicit flow (response_type=token) accepted', 'severity': 'MEDIUM'})
            # NEW: Open redirect check
            if sym == 'AuthorizeOpenRedirect' and res in ('Redirect', 'Success'):
                findings.append({'type': 'OPEN_REDIRECT', 'detail': 'Malicious redirect_uri accepted', 'severity': 'HIGH'})
        return findings

    def _get_response_at(self, idx: int):
        """Get the response object at a given sequence index from received_data."""
        try:
            if self.oauth_protocol and self.oauth_protocol.received_data and idx < len(self.oauth_protocol.received_data):
                return self.oauth_protocol.received_data[idx]
        except Exception:
            pass
        return None

    def state_consistency(self) -> List[Dict]:
        findings = []
        revoke_meta = (getattr(self.oauth_protocol, 'action_meta', {}) or {}).get('revoke_token', {})
        if revoke_meta:
            tok_candidates = []
            try:
                tok_candidates.append(self.oauth_protocol.access_token)
                tok_candidates.append(self.oauth_protocol.refresh_token_value)
            except Exception:
                pass
            for t in [x for x in tok_candidates if x]:
                rt, ir = self.oauth_protocol.introspect(token=t)
                body = {}
                try:
                    body_text = getattr(ir, 'text', '') or ''
                    import json as _json
                    body = _json.loads(body_text)
                except Exception:
                    pass
                if ir.status_code == 200 and bool(body.get('active', False)):
                    findings.append({'type': 'REVOKE_NOT_EFFECTIVE', 'detail': f'Introspect active=true after revoke (token_kind={revoke_meta.get("token_kind")})', 'severity': 'HIGH'})
                    break

        refresh_meta = (getattr(self.oauth_protocol, 'action_meta', {}) or {}).get('refresh_token', {})
        prev = refresh_meta.get('prev_access_token')
        if prev:
            rt, ur = self.oauth_protocol.userinfo(access_token=prev)
            if ur.status_code == 200:
                findings.append({'type': 'OLD_TOKEN_STILL_VALID', 'detail': 'Old access_token still valid after refresh', 'severity': 'MEDIUM'})
        return findings

    def token_semantics(self) -> List[Dict]:
        findings = []
        for tok_name in ('access_token', 'id_token'):
            token = getattr(self.oauth_protocol, tok_name, None)
            if not token:
                continue
            header, payload = self._decode_jwt(token)
            alg = (header.get('alg') or '').upper()
            if alg == 'NONE':
                findings.append({'type': 'JWT_ALG_NONE', 'detail': f'{tok_name} alg=none', 'severity': 'HIGH'})
            now = int(time.time())
            exp = payload.get('exp')
            iat = payload.get('iat')
            if isinstance(exp, int) and exp < now:
                findings.append({'type': 'JWT_EXPIRED', 'detail': f'{tok_name} expired', 'severity': 'MEDIUM'})
            if isinstance(iat, int) and iat > now + 300:
                findings.append({'type': 'JWT_FUTURE_IAT', 'detail': f'{tok_name} iat in future', 'severity': 'LOW'})
            scope = payload.get('scope') or ''
            if tok_name == 'access_token' and ('openid' not in scope):
                findings.append({'type': 'JWT_SCOPE_SUSPECT', 'detail': 'access_token scope missing openid', 'severity': 'LOW'})
        return findings

    def scope_escalation_check(self, requested_scope: str = None) -> List[Dict]:
        """Check for unauthorized scope escalation"""
        findings = []
        
        if not self.oauth_protocol.access_token:
            return findings
        
        header, payload = self._decode_jwt(self.oauth_protocol.access_token)
        granted_scope = set((payload.get('scope') or '').split())
        
        # Use config scope as baseline if not provided
        config_scope = getattr(self.oauth_protocol.config, 'scope', 'openid profile email')
        requested = set((requested_scope or config_scope).split())
        
        # Check for extra scopes not requested
        extra_scopes = granted_scope - requested - {'openid'}
        if extra_scopes:
            findings.append({
                'type': 'SCOPE_ESCALATION',
                'detail': f'Granted extra scopes not requested: {extra_scopes}',
                'severity': 'HIGH'
            })
        
        # Check for admin/privileged scopes
        privileged_scopes = {'admin', 'manage-users', 'manage-realm', 'impersonation', 
                           'view-users', 'manage-clients', 'realm-admin'}
        granted_privileged = granted_scope & privileged_scopes
        if granted_privileged:
            findings.append({
                'type': 'PRIVILEGED_SCOPE_GRANTED',
                'detail': f'Privileged scopes in token: {granted_privileged}',
                'severity': 'CRITICAL'
            })
        
        return findings

    def token_confusion_check(self) -> List[Dict]:
        """Check for token type confusion vulnerabilities"""
        findings = []
        
        # Try using refresh_token as access_token
        refresh_token = getattr(self.oauth_protocol, 'refresh_token_value', None)
        if refresh_token:
            try:
                import requests
                headers = {'Authorization': f'Bearer {refresh_token}'}
                resp = requests.get(self.oauth_protocol.userinfo_endpoint, headers=headers, timeout=5)
                
                if resp.status_code == 200:
                    findings.append({
                        'type': 'TOKEN_CONFUSION_REFRESH',
                        'detail': 'Refresh token accepted as access token at userinfo endpoint',
                        'severity': 'CRITICAL'
                    })
            except Exception:
                pass
        
        # Try using id_token as access_token
        id_token = getattr(self.oauth_protocol, 'id_token', None)
        if id_token:
            try:
                import requests
                headers = {'Authorization': f'Bearer {id_token}'}
                resp = requests.get(self.oauth_protocol.userinfo_endpoint, headers=headers, timeout=5)
                
                if resp.status_code == 200:
                    findings.append({
                        'type': 'TOKEN_CONFUSION_ID',
                        'detail': 'ID token accepted as access token at userinfo endpoint',
                        'severity': 'HIGH'
                    })
            except Exception:
                pass
        
        return findings

    def pkce_enforcement_check(self, sequence: List[str], results: List[str]) -> List[Dict]:
        """Check if PKCE is properly enforced"""
        findings = []

        # Legacy-Oracle toggle (strict-vs-legacy oracle precision experiment):
        # OAuth 2.0 (RFC 6749) does not require PKCE; a legacy-strict oracle
        # must not flag its absence. Enabled via OAUTH_FUZZ_ORACLE_LEGACY=1.
        import os as _os
        if _os.environ.get('OAUTH_FUZZ_ORACLE_LEGACY') == '1':
            return findings

        # Check if AuthorizeNoPKCE followed by successful TokenExchange
        for i, (sym, res) in enumerate(zip(sequence, results)):
            if sym == 'AuthorizeNoPKCE' and res in ('Success', 'Redirect'):
                # Look for subsequent successful TokenExchange
                for j in range(i+1, len(sequence)):
                    if sequence[j] == 'TokenExchange' and results[j] == 'Success':
                        findings.append({
                            'type': 'PKCE_NOT_ENFORCED',
                            'detail': 'Token exchange succeeded without PKCE',
                            'severity': 'HIGH'
                        })
                        break
        
        return findings

    def evaluate(self, sequence: List[str], results: List[str]) -> List[Dict]:
        f = []
        try:
            f += self.rfc_compliance(sequence, results)
            f += self.state_consistency()
            f += self.token_semantics()
            f += self.scope_escalation_check()
            f += self.token_confusion_check()
            f += self.pkce_enforcement_check(sequence, results)
        except Exception as e:
            f.append({'type': 'ORACLE_ERROR', 'detail': str(e), 'severity': 'LOW'})
        return f

    def quick_oracle(self, sequence: List[str], results: List[str], target_type: str = 'keycloak') -> List[Dict]:
        """Enhanced quick vulnerability check for sequence results"""
        findings = []
        
        for idx, (sym, res) in enumerate(zip(sequence, results)):
            # Check all vulnerability indicators
            ctx = {}
            for vuln_id, vuln_spec in self.vuln_indicators.items():
                try:
                    if vuln_spec['condition'](sym, res, sequence, ctx):
                        finding = {
                            'type': vuln_id.upper(),
                            'severity': vuln_spec['severity'],
                            'cwe': vuln_spec['cwe'],
                            'detail': vuln_spec['description'],
                            'symbol': sym,
                            'result': res,
                            'sequence_position': idx,
                            'full_sequence': sequence,
                            'target_type': target_type
                        }
                        findings.append(finding)
                except Exception:
                    continue
            
            # Check response body for vulnerability patterns
            if self.oauth_protocol and self.oauth_protocol.received_data and idx < len(self.oauth_protocol.received_data):
                body = str(self.oauth_protocol.received_data[idx])
                for pattern, vuln_type, description in self.body_vuln_patterns:
                    import re
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append({
                            'type': vuln_type,
                            'severity': 'MEDIUM',
                            'detail': description,
                            'symbol': sym,
                            'pattern_matched': pattern,
                            'target_type': target_type
                        })
        
        # Check sequence-level vulnerabilities
        findings.extend(self._check_sequence_level_vulns(sequence, results, target_type))
        
        return findings
    
    def _check_sequence_level_vulns(self, sequence: List[str], results: List[str], target_type: str) -> List[Dict]:
        """Check for vulnerabilities that span multiple steps"""
        findings = []
        
        # Authorization code replay
        if sequence.count('TokenExchange') > 1:
            token_results = [r for s, r in zip(sequence, results) if s == 'TokenExchange']
            success_count = sum(1 for r in token_results if r in ('Success', '200'))
            if success_count > 1:
                findings.append({
                    'type': 'CODE_REPLAY',
                    'severity': 'CRITICAL',
                    'cwe': 'CWE-384',
                    'detail': f'Authorization code accepted {success_count} times',
                    'target_type': target_type
                })
        
        # Refresh token replay — only flag if a token was actually obtained first
        if sequence.count('RefreshToken') > 1:
            has_prior_token = any(
                s in ('TokenExchange', 'PasswordGrant', 'ClientCredentials') and r in ('Success', '200')
                for s, r in zip(sequence, results)
            )
            if has_prior_token:
                # Compute MAX-CONSECUTIVE refresh successes.
                # Chain refreshing (protocol/base.py rotates refresh_token_value
                # after every success) is RFC 6749 §6 behavior — it is NOT replay.
                # True replay requires the SAME literal refresh_token value to be
                # accepted more than once. The framework does not capture the
                # literal value here, so we use "extremely unusual chain length"
                # as a weak proxy and severity-downgrade everything else.
                consecutive = 0
                max_consecutive = 0
                total_success  = 0
                for sym, res in zip(sequence, results):
                    if sym == 'RefreshToken' and res in ('Success', '200'):
                        consecutive += 1
                        total_success += 1
                        if consecutive > max_consecutive:
                            max_consecutive = consecutive
                    else:
                        consecutive = 0

                # Also check whether the sequence shows a non-consecutive reuse
                # pattern (refresh, something else that would invalidate, refresh).
                # Treat PasswordGrant / TokenExchange / Login between refreshes as
                # a re-auth, which makes "replay" suspicion higher.
                reauth_between = False
                last_refresh_idx = -1
                for i, (sym, res) in enumerate(zip(sequence, results)):
                    if sym == 'RefreshToken' and res in ('Success', '200'):
                        if last_refresh_idx >= 0:
                            middle = sequence[last_refresh_idx + 1:i]
                            if any(m in ('PasswordGrant', 'TokenExchange', 'Login',
                                         'RevokeToken', 'AutheliaLogout') for m in middle):
                                reauth_between = True
                        last_refresh_idx = i

                if max_consecutive >= 5:
                    findings.append({
                        'type': 'REFRESH_REPLAY',
                        'severity': 'HIGH',
                        'cwe': 'CWE-384',
                        'detail': f'Refresh token chain of {max_consecutive} consecutive successes (unusual length)',
                        'target_type': target_type
                    })
                elif reauth_between and total_success >= 2:
                    findings.append({
                        'type': 'REFRESH_REPLAY',
                        'severity': 'LOW',
                        'cwe': 'CWE-384',
                        'detail': 'RefreshToken success bracketing a re-auth step (possible replay)',
                        'target_type': target_type
                    })
                # Otherwise: normal chain refresh, DO NOT emit a finding.
        
        # Skipped authentication steps
        if 'TokenExchange' in sequence and 'Login' not in sequence:
            te_idx = sequence.index('TokenExchange')
            te_result = results[te_idx] if te_idx < len(results) else ''
            if te_result in ('Success', '200'):
                findings.append({
                    'type': 'AUTH_STEP_BYPASS',
                    'severity': 'CRITICAL',
                    'cwe': 'CWE-287',
                    'detail': 'Token obtained without user authentication',
                    'target_type': target_type
                })
        
        # Revoked token still valid (Authelia-specific)
        if target_type == 'authelia':
            if 'AutheliaLogout' in sequence and 'RefreshToken' in sequence:
                logout_idx = sequence.index('AutheliaLogout')
                refresh_indices = [i for i, s in enumerate(sequence) if s == 'RefreshToken']
                for ref_idx in refresh_indices:
                    if ref_idx > logout_idx:
                        ref_result = results[ref_idx] if ref_idx < len(results) else ''
                        if ref_result in ('Success', '200'):
                            findings.append({
                                'type': 'TOKEN_NOT_REVOKED',
                                'severity': 'HIGH',
                                'cwe': 'CWE-613',
                                'detail': 'Refresh token valid after logout',
                                'target_type': target_type
                            })

        return findings

    def _response_contains_error(self, response) -> bool:
        """Check if a 200 response actually contains an OAuth error in the body."""
        if response is None:
            return True
        try:
            body = response.text or ''
            if '"error"' in body or '"error_description"' in body:
                return True
            import json
            data = json.loads(body)
            if 'error' in data:
                return True
        except Exception:
            pass
        return False

    def _last_response_is_real_success(self) -> bool:
        """Check if the most recent response from the SUT is a genuine success (not an error in 200 body)."""
        try:
            if self.oauth_protocol and self.oauth_protocol.received_data:
                last_resp = self.oauth_protocol.received_data[-1]
                if hasattr(last_resp, 'text'):
                    body = last_resp.text or ''
                    if '"error"' in body or '"error_description"' in body:
                        return False
                    import json
                    try:
                        data = json.loads(body)
                        if 'error' in data:
                            return False
                    except (json.JSONDecodeError, ValueError):
                        pass
        except Exception:
            pass
        return True

class RaceConditionTester:
    """Test for race conditions in OAuth flows"""
    
    def __init__(self, oauth_config: Dict):
        self.oauth_config = oauth_config
        self.findings = []
    
    def test_code_race(self, auth_code: str, token_endpoint: str, 
                       client_id: str, client_secret: str, 
                       redirect_uri: str, code_verifier: str,
                       num_requests: int = 5) -> Optional[Dict]:
        """Race condition: multiple token exchanges with same code"""
        if not auth_code:
            return None
        
        import requests
        results = []
        barrier = threading.Barrier(num_requests)
        
        def exchange_code():
            try:
                barrier.wait(timeout=5)
                resp = requests.post(token_endpoint, data={
                    'grant_type': 'authorization_code',
                    'code': auth_code,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'redirect_uri': redirect_uri,
                    'code_verifier': code_verifier
                }, timeout=10)
                return resp.status_code
            except Exception:
                return 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [executor.submit(exchange_code) for _ in range(num_requests)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        success_count = sum(1 for r in results if r == 200)
        if success_count > 1:
            return {
                'type': 'CODE_RACE_CONDITION',
                'detail': f'Authorization code accepted {success_count} times (expected max 1)',
                'severity': 'CRITICAL',
                'results': results
            }
        return None
    
    def test_refresh_race(self, refresh_token: str, token_endpoint: str,
                          client_id: str, client_secret: str,
                          num_requests: int = 5) -> Optional[Dict]:
        """Race condition: concurrent refresh token usage"""
        if not refresh_token:
            return None
        
        import requests
        barrier = threading.Barrier(num_requests)
        tokens_received = []
        lock = threading.Lock()
        
        def refresh():
            try:
                barrier.wait(timeout=5)
                resp = requests.post(token_endpoint, data={
                    'grant_type': 'refresh_token',
                    'refresh_token': refresh_token,
                    'client_id': client_id,
                    'client_secret': client_secret
                }, timeout=10)
                if resp.status_code == 200:
                    try:
                        new_refresh = resp.json().get('refresh_token')
                        with lock:
                            tokens_received.append(new_refresh)
                    except:
                        pass
                return resp.status_code
            except Exception:
                return 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_requests) as executor:
            futures = [executor.submit(refresh) for _ in range(num_requests)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        unique_tokens = set(t for t in tokens_received if t)
        if len(unique_tokens) > 1:
            return {
                'type': 'REFRESH_TOKEN_RACE',
                'detail': f'Multiple different refresh tokens issued: {len(unique_tokens)}',
                'severity': 'HIGH',
                'token_count': len(unique_tokens)
            }
        return None