#!/usr/bin/env python3
"""
OAuth System Under Test (SUT) for Keycloak Fuzzing
Handles target service lifecycle and fuzzing query execution
"""

import subprocess
import socket
import time
import signal
import os
from typing import List, Tuple, Optional, Dict, Any
from aalpy.base import SUL
from OAuthMapper.OAuthProtocol import OAuthProtocol, OAuthConfig


class OAuthSUT(SUL):
    """
    OAuth System Under Test implementation for Keycloak fuzzing
    Manages Keycloak service lifecycle and executes fuzzing queries
    """
    
    def __init__(self, config: OAuthConfig, target_cmd: Optional[str] = None, 
                 keycloak_config: Optional[Dict] = None, target_type: str = 'keycloak'):
        super().__init__()
        self.config = config
        self.target_cmd = target_cmd
        self.keycloak_config = keycloak_config or {}
        self.target_type = target_type.lower()
        self.target_process = None
        self.target_ip = None
        self.target_port = None
        self.oauth_protocol = None
        self.symbol_overrides: Dict[str, Any] = {}
        self._last_response = None

        # Targets that use standard symbol names without remapping via
        # a target-specific symbol_map. These targets dispatch directly
        # through the method_map using unmodified symbol names.
        # Note: "generic" here means "no symbol remapping", not "all OIDC
        # targets" — other OIDC targets (authelia, casdoor, hydra, zitadel,
        # shiro, authentik, simplelogin, nodeoidc) have dedicated symbol_map
        # entries that remap Authorize/Login/AuthCodeRedirect etc.
        self._generic_oidc_targets = {'spring_authz', 'cxf_oauth', 'wso2', 'logto'}
        
        if 'target' in self.keycloak_config:
            self.target_ip, self.target_port = self.keycloak_config['target']
        else:
            from urllib.parse import urlparse
            parsed = urlparse(config.base_url)
            self.target_ip = parsed.hostname or '127.0.0.1'
            self.target_port = parsed.port or 8080
        
        if self.target_type == 'authelia':
            self._configure_authelia_endpoints()
        elif self.target_type == 'casdoor':
            self._configure_casdoor_endpoints()
        elif self.target_type == 'ory_hydra':
            self._configure_ory_hydra_endpoints()
        elif self.target_type == 'zitadel':
            self._configure_zitadel_endpoints()
    
    def _configure_authelia_endpoints(self):
        """Configure OAuth protocol endpoints for Authelia"""
        if self.oauth_protocol is None:
            self.oauth_protocol = OAuthProtocol(self.config)
        
        base_url = self.config.base_url
        proto = self.oauth_protocol
        
        # Standard OIDC endpoints
        proto.auth_endpoint = f"{base_url}/api/oidc/authorization"
        proto.token_endpoint = f"{base_url}/api/oidc/token"
        proto.userinfo_endpoint = f"{base_url}/api/oidc/userinfo"
        proto.introspect_endpoint = f"{base_url}/api/oidc/introspection"
        proto.revoke_endpoint = f"{base_url}/api/oidc/revocation"
        
        # Authelia-specific endpoints
        proto.firstfactor_endpoint = f"{base_url}/api/firstfactor"
        proto.secondfactor_totp_endpoint = f"{base_url}/api/secondfactor/totp"
        proto.secondfactor_webauthn_endpoint = f"{base_url}/api/secondfactor/webauthn"
        proto.logout_endpoint = f"{base_url}/api/logout"
        proto.state_endpoint = f"{base_url}/api/state"
        proto.consent_endpoint = f"{base_url}/api/oidc/consent"
        proto.configuration_endpoint = f"{base_url}/api/configuration"

    def _configure_casdoor_endpoints(self):
        """Configure OAuth protocol endpoints for Casdoor"""
        if self.oauth_protocol is None:
            self.oauth_protocol = OAuthProtocol(self.config)

        base_url = self.config.base_url
        proto = self.oauth_protocol

        proto.auth_endpoint = f"{base_url}/api/login/oauth/authorize"
        proto.token_endpoint = f"{base_url}/api/login/oauth/access_token"
        proto.userinfo_endpoint = f"{base_url}/api/userinfo"
        proto.introspect_endpoint = f"{base_url}/api/login/oauth/introspect"
        proto.jwks_endpoint = f"{base_url}/.well-known/jwks"
        proto.discovery_url = f"{base_url}/.well-known/openid-configuration"
        proto._casdoor_auto_signin_url = f"{base_url}/api/auto-signin"

    def _configure_ory_hydra_endpoints(self):
        """Configure OAuth protocol endpoints for Ory Hydra"""
        if self.oauth_protocol is None:
            self.oauth_protocol = OAuthProtocol(self.config)

        base_url = self.config.base_url
        proto = self.oauth_protocol

        proto.auth_endpoint = f"{base_url}/oauth2/auth"
        proto.token_endpoint = f"{base_url}/oauth2/token"
        proto.userinfo_endpoint = f"{base_url}/userinfo"
        proto.introspect_endpoint = f"{base_url}/admin/oauth2/introspect"
        proto.revoke_endpoint = f"{base_url}/oauth2/revoke"
        proto.jwks_endpoint = f"{base_url}/.well-known/jwks.json"
        proto.par_endpoint = f"{base_url}/oauth2/par"
        proto.discovery_url = f"{base_url}/.well-known/openid-configuration"
        proto._hydra_admin_url = f"{base_url}/admin"

    def _configure_zitadel_endpoints(self):
        """Configure OAuth protocol endpoints for Zitadel"""
        if self.oauth_protocol is None:
            self.oauth_protocol = OAuthProtocol(self.config)

        base_url = self.config.base_url
        proto = self.oauth_protocol

        proto.auth_endpoint = f"{base_url}/oauth/v2/authorize"
        proto.token_endpoint = f"{base_url}/oauth/v2/token"
        proto.userinfo_endpoint = f"{base_url}/oidc/v1/userinfo"
        proto.introspect_endpoint = f"{base_url}/oauth/v2/introspect"
        proto.revoke_endpoint = f"{base_url}/oauth/v2/revoke"
        proto.jwks_endpoint = f"{base_url}/oauth/v2/keys"
        proto.end_session_endpoint = f"{base_url}/oidc/v1/end_session"
        proto.par_endpoint = f"{base_url}/oauth/v2/par"
        proto.discovery_url = f"{base_url}/.well-known/openid-configuration"
        proto._zitadel_api_base = f"{base_url}/management/v1"
    
    def reset(self):
        """Reset OAuth protocol state for new fuzzing iteration"""
        if self.oauth_protocol is None:
            self.oauth_protocol = OAuthProtocol(self.config)
        else:
            self.oauth_protocol.reset()
        
        # Test connectivity to target
        if not self._test_connectivity():
            raise ConnectionError(f"Cannot connect to {self.target_type} at {self.target_ip}:{self.target_port}")
        
        return True
    
    def _test_connectivity(self, timeout: float = 5.0) -> bool:
        """Test if OAuth service is reachable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_ip, self.target_port))
            sock.close()
            return result == 0
        except:
            return False
    
    def step(self, letter):
        """
        Execute a single input symbol (required by aalpy SUL abstract class).
        
        Args:
            letter: The input symbol to execute (OAuth operation name)
            
        Returns:
            str: The output/response status from executing the symbol
        """
        return self.execute_symbol(letter)
    
    def pre(self):
        """Start target service if needed"""
        if self.target_cmd:
            try:
                # Set up environment for Keycloak
                env = os.environ.copy()
                
                # Add any Keycloak-specific environment variables
                if 'KEYCLOAK_ADMIN' in self.keycloak_config:
                    env['KEYCLOAK_ADMIN'] = self.keycloak_config['KEYCLOAK_ADMIN']
                if 'KEYCLOAK_ADMIN_PASSWORD' in self.keycloak_config:
                    env['KEYCLOAK_ADMIN_PASSWORD'] = self.keycloak_config['KEYCLOAK_ADMIN_PASSWORD']
                
                # Start target process
                self.target_process = subprocess.Popen(
                    self.target_cmd,
                    shell=False,
                    stdin=None,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env
                )
                
                # Wait for service to be ready
                max_wait = 30  # seconds
                wait_interval = 0.5
                waited = 0
                
                while waited < max_wait:
                    if self._test_connectivity(timeout=1.0):
                        break
                    time.sleep(wait_interval)
                    waited += wait_interval
                
                
            except Exception as e:
                pass
        
        # Initialize OAuth protocol
        self.reset()
    
    def post(self):
        """Clean up after fuzzing iteration"""
        if self.target_process:
            try:
                # Send SIGINT to gracefully shutdown
                self.target_process.send_signal(signal.SIGINT)
                self.target_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Force kill if graceful shutdown fails
                self.target_process.kill()
                self.target_process.wait()
            except:
                pass
            finally:
                self.target_process = None
    
    def set_symbol_overrides(self, overrides: Dict[str, Any]):
        """设置符号级参数覆盖，用于外部适配器注入变异参数"""
        self.symbol_overrides = overrides or {}

    def _mutation_tags(self, symbol: str) -> List[str]:
        """根据覆盖参数推断具体变异类型标签"""
        tags: List[str] = []
        ovr = self.symbol_overrides.get(symbol, {}) if isinstance(self.symbol_overrides, dict) else {}
        if not isinstance(ovr, dict) or not ovr:
            # Add inherent tags for security-focused symbols
            security_symbol_tags = {
                'AuthorizeImplicit': ['implicit_flow'],
                'AuthorizeHybrid': ['hybrid_flow'],
                'AuthorizeHybridIDToken': ['hybrid_flow', 'id_token'],
                'AuthorizeOpenRedirect': ['open_redirect'],
                'AuthorizeRedirectSSRF': ['ssrf_redirect'],
                'AuthorizeScopeEscalation': ['scope_escalation'],
                'AuthorizeScopeAdmin': ['scope_admin'],
                'AuthorizePKCEMethodConfusion': ['pkce_confusion'],
                'UseRefreshAsAccess': ['token_confusion', 'refresh_as_access'],
                'UseIDTokenAsAccess': ['token_confusion', 'id_as_access'],
                'TokenExchangeNoPKCE': ['pkce_downgrade'],
                'TokenExchangeWrongClient': ['cross_client'],
                'TokenExchangeInvalidClient': ['client_enum'],
                'PushedAuthorizationRequest': ['par'],
                'AuthorizePAR': ['par'],
            }
            if symbol in security_symbol_tags:
                return security_symbol_tags[symbol]
            return tags

        # Authorize 相关
        if symbol in ('Authorize', 'AuthorizeNoPKCE', 'AuthorizePKCES256', 'AuthorizePKCEPlain',
                      'AuthorizeImplicit', 'AuthorizeHybrid', 'AuthorizeHybridIDToken',
                      'AuthorizeOpenRedirect', 'AuthorizeScopeEscalation', 'AuthorizeScopeAdmin',
                      'AuthorizePKCEMethodConfusion'):
            if 'code_challenge_method' in ovr and str(ovr.get('code_challenge_method')).lower() == 'plain':
                tags.append('pkce_plain')
            if 'state' in ovr:
                tags.append('state_mismatch')
            if 'nonce' in ovr:
                tags.append('nonce_mut')
            if 'redirect_uri' in ovr:
                try:
                    from urllib.parse import urlparse
                    ru = urlparse(str(ovr.get('redirect_uri')))
                    bu = urlparse(self.config.base_url)
                    if ru.hostname and bu.hostname and ru.hostname != bu.hostname:
                        tags.append('bad_redirect')
                    else:
                        tags.append('redirect_param')
                except Exception:
                    tags.append('redirect_param')
            if 'scope' in ovr:
                tags.append('scope_mutation')

        # TokenExchange/Refresh/Revoke/Introspect 客户端认证与PKCE
        if symbol in ('TokenExchange', 'RefreshToken', 'RevokeToken', 'Introspect', 'ClientCredentials',
                      'TokenExchangeNoPKCE', 'TokenExchangeWrongClient', 'TokenExchangeInvalidClient'):
            if 'client_auth' in ovr and str(ovr.get('client_auth')).lower() == 'basic':
                tags.append('client_auth_basic')
            if symbol == 'TokenExchange':
                if 'client_secret' in ovr:
                    try:
                        cfg_secret = getattr(self.config, 'client_secret', None)
                        if cfg_secret and ovr.get('client_secret') != cfg_secret:
                            tags.append('wrong_secret')
                        else:
                            tags.append('secret_override')
                    except Exception:
                        tags.append('secret_override')
                if 'code_verifier' in ovr:
                    tags.append('pkce_edge')

        # UserInfo
        if symbol == 'UserInfo':
            if 'authorization' in ovr:
                tags.append('jwt_variant')

        # Token confusion attacks
        if symbol in ('UseRefreshAsAccess', 'UseIDTokenAsAccess'):
            tags.append('token_confusion')

        # 无效令牌场景
        if symbol in ('UserInfoWrongToken', 'TokenWrongClientSecret', 'TokenBadCode'):
            if symbol == 'UserInfoWrongToken':
                tags.append('invalid_token')
            elif symbol == 'TokenWrongClientSecret':
                tags.append('wrong_secret')
            elif symbol == 'TokenBadCode':
                tags.append('bad_code')

        return tags

    def _mutation_detail(self, symbol: str) -> str:
        """构造安全的变异参数摘要，避免泄露敏感信息"""
        ovr = self.symbol_overrides.get(symbol, {}) if isinstance(self.symbol_overrides, dict) else {}
        details = []
        try:
            if symbol == 'RevokeToken':
                mode = str(ovr.get('client_auth', 'post'))
                if mode.lower() == 'basic':
                    details.append(f"client_auth={mode}")
                meta = getattr(self.oauth_protocol, 'action_meta', {}) or {}
                rv = meta.get('revoke_token', {})
                tk = rv.get('token_kind')
                if tk and tk != 'unknown':
                    details.append(f"token_kind={tk}")
                hint = rv.get('token_hint', None)
                if hint is not None:
                    details.append(f"token_hint={hint or 'none'}")
                ah = rv.get('auth_header')
                if ah == 'Basic':
                    details.append(f"auth_header={ah}")
            elif symbol == 'Introspect':
                mode = str(ovr.get('client_auth', 'post'))
                if mode.lower() == 'basic':
                    details.append(f"client_auth={mode}")
                meta = getattr(self.oauth_protocol, 'action_meta', {}) or {}
                it = meta.get('introspect', {})
                tk = it.get('token_kind')
                if tk and tk != 'unknown':
                    details.append(f"token_kind={tk}")
                ah = it.get('auth_header')
                if ah == 'Basic':
                    details.append(f"auth_header={ah}")
            elif symbol == 'TokenExchange':
                mode = str(ovr.get('client_auth', 'post'))
                if mode.lower() == 'basic':
                    details.append(f"client_auth={mode}")
                if 'code_verifier' in ovr:
                    details.append("code_verifier=mutated")
            elif symbol in ('Authorize', 'AuthorizeNoPKCE', 'AuthorizePKCES256', 'AuthorizePKCEPlain'):
                if 'code_challenge_method' in ovr:
                    details.append(f"code_challenge_method={ovr.get('code_challenge_method')}")
                if 'state' in ovr:
                    details.append("state=mutated")
                if 'nonce' in ovr:
                    details.append("nonce=mutated")
            elif symbol == 'UserInfo':
                if 'authorization' in ovr:
                    details.append("authorization=jwt_variant")
        except Exception:
            pass
        return '; '.join(details)

    def execute_symbol(self, symbol: str) -> str:
        """Execute a symbol and return response status"""
        try:
            actual_symbol = symbol

            if self.target_type == 'authelia':
                authelia_symbol_map = {
                    'Authorize': 'AutheliaAuthorize',
                    'AuthorizeNoPKCE': 'AutheliaAuthorize',
                    'AuthorizePKCES256': 'AutheliaAuthorize',
                    'AuthorizePKCEPlain': 'AutheliaAuthorize',
                    'Login': 'AutheliaLogin',
                    'AuthCodeRedirect': 'AutheliaAuthCodeRedirect',
                    # Audit-pack mappings (SECURITY_AUDIT.md §7)
                    'AutheliaConsentIDFuzz': 'AutheliaConsentIDFuzz',
                    'AutheliaParFlood': 'AutheliaParFlood',
                    'AutheliaAuthorizeAfter1FA': 'AutheliaAuthorizeAfter1FA',
                    'AutheliaConsentSubjectSwap': 'AutheliaConsentSubjectSwap',
                    'AutheliaSessionRegenCheck': 'AutheliaSessionRegenCheck',
                    'AutheliaPKCEMethodConfusion': 'AutheliaPKCEMethodConfusion',
                    'AutheliaRedirectMismatchToken': 'AutheliaRedirectMismatchToken',
                    'AutheliaIntrospectCrossClient': 'AutheliaIntrospectCrossClient',
                    'AutheliaUserinfoAlgNone': 'AutheliaUserinfoAlgNone',
                    'AutheliaForwardAuthSpoof': 'AutheliaForwardAuthSpoof',
                }
                if symbol in authelia_symbol_map:
                    actual_symbol = authelia_symbol_map[symbol]

            elif self.target_type == 'wso2':
                wso2_symbol_map = {
                    'Authorize': 'Wso2Authorize',
                    'Login': 'Wso2Login',
                    'AuthCodeRedirect': 'Wso2AuthCodeRedirect',
                    'Introspect': 'Wso2Introspect',
                }
                if symbol in wso2_symbol_map:
                    actual_symbol = wso2_symbol_map[symbol]

            elif self.target_type == 'casdoor':
                casdoor_symbol_map = {
                    'Authorize': 'CasdoorAuthorize',
                    'AuthorizeNoPKCE': 'CasdoorAuthorize',
                    'AuthorizePKCES256': 'CasdoorAuthorize',
                    'Login': 'CasdoorLogin',
                    'AuthCodeRedirect': 'CasdoorAuthCodeRedirect',
                    'Consent': 'CasdoorConsent',
                }
                if symbol in casdoor_symbol_map:
                    actual_symbol = casdoor_symbol_map[symbol]

            elif self.target_type == 'ory_hydra':
                hydra_symbol_map = {
                    'Authorize': 'HydraAuthorize',
                    'AuthorizeNoPKCE': 'HydraAuthorize',
                    'AuthorizePKCES256': 'HydraAuthorize',
                    'Login': 'HydraLogin',
                    'AuthCodeRedirect': 'HydraAuthCodeRedirect',
                    'Consent': 'HydraConsent',
                }
                if symbol in hydra_symbol_map:
                    actual_symbol = hydra_symbol_map[symbol]

            elif self.target_type == 'zitadel':
                zitadel_symbol_map = {
                    'Authorize': 'ZitadelAuthorize',
                    'AuthorizeNoPKCE': 'ZitadelAuthorize',
                    'AuthorizePKCES256': 'ZitadelAuthorize',
                    'Login': 'ZitadelLogin',
                    'AuthCodeRedirect': 'ZitadelAuthCodeRedirect',
                    'Consent': 'ZitadelConsent',
                }
                if symbol in zitadel_symbol_map:
                    actual_symbol = zitadel_symbol_map[symbol]

            elif self.target_type == 'authentik':
                authentik_symbol_map = {
                    'Authorize': 'AuthentikAuthorize',
                    'AuthorizeNoPKCE': 'AuthentikAuthorize',
                    'AuthorizePKCES256': 'AuthentikAuthorize',
                    'Login': 'AuthentikLogin',
                    'AuthCodeRedirect': 'AuthentikAuthCodeRedirect',
                    'AuthentikFlowStageBypass': 'AuthentikFlowStageBypass',
                    'AuthentikCSRFTokenReuse': 'AuthentikCSRFTokenReuse',
                    'AuthentikDeviceCodeFuzz': 'AuthentikDeviceCodeFuzz',
                    'AuthentikIntrospectCrossClient': 'AuthentikIntrospectCrossClient',
                    'AuthentikTokenConfusion': 'AuthentikTokenConfusion',
                    'AuthentikScopeEscalation': 'AuthentikScopeEscalation',
                    'AuthentikEndSessionRedirect': 'AuthentikEndSessionRedirect',
                }
                if symbol in authentik_symbol_map:
                    actual_symbol = authentik_symbol_map[symbol]

            elif self.target_type == 'simplelogin':
                simplelogin_symbol_map = {
                    'Authorize': 'SimpleLoginAuthorize',
                    'AuthorizeNoPKCE': 'SimpleLoginAuthorize',
                    'AuthorizePKCES256': 'SimpleLoginAuthorize',
                    'Login': 'SimpleLoginLogin',
                    'AuthCodeRedirect': 'SimpleLoginAuthCodeRedirect',
                    'SimpleLoginCSRFByass': 'SimpleLoginCSRFByass',
                    'SimpleLoginOpenRedirect': 'SimpleLoginOpenRedirect',
                    'SimpleLoginTokenReplay': 'SimpleLoginTokenReplay',
                    'SimpleLoginScopeManipulation': 'SimpleLoginScopeManipulation',
                    'SimpleLoginClientImpersonation': 'SimpleLoginClientImpersonation',
                }
                if symbol in simplelogin_symbol_map:
                    actual_symbol = simplelogin_symbol_map[symbol]

            elif self.target_type == 'nodeoidc':
                nodeoidc_symbol_map = {
                    'Authorize': 'NodeOIDCAuthorize',
                    'AuthorizeNoPKCE': 'NodeOIDCAuthorize',
                    'AuthorizePKCES256': 'NodeOIDCAuthorize',
                    'Login': 'NodeOIDCLogin',
                    'AuthCodeRedirect': 'NodeOIDCAuthCodeRedirect',
                    'NodeOIDCPKCEPlain': 'NodeOIDCPKCEPlain',
                    'NodeOIDCCodeReplay': 'NodeOIDCCodeReplay',
                    'NodeOIDCInvalidVerifier': 'NodeOIDCInvalidVerifier',
                    'NodeOIDCIntrospectCrossClient': 'NodeOIDCIntrospectCrossClient',
                    'NodeOIDCScopeEscalation': 'NodeOIDCScopeEscalation',
                }
                if symbol in nodeoidc_symbol_map:
                    actual_symbol = nodeoidc_symbol_map[symbol]

            elif self.target_type in self._generic_oidc_targets:
                pass

            method_map = {
                # Standard OAuth Symbols (Keycloak-optimized)
                'Authorize': self.oauth_protocol.authorize,
                'AuthorizeNoPKCE': self.oauth_protocol.authorize_no_pkce,
                'Login': self.oauth_protocol.login,
                'AuthCodeRedirect': self.oauth_protocol.auth_code_redirect,
                'TokenExchange': self.oauth_protocol.token_exchange,
                'UserInfo': self.oauth_protocol.userinfo,
                'TokenBadCode': self.oauth_protocol.token_bad_code,
                'TokenWrongClientSecret': self.oauth_protocol.token_wrong_client_secret,
                'UserInfoWrongToken': self.oauth_protocol.userinfo_wrong_token,
                'PasswordGrant': self.oauth_protocol.password_grant,
                'ClientCredentials': self.oauth_protocol.client_credentials,
                'RefreshToken': self.oauth_protocol.refresh_token,
                'Introspect': self.oauth_protocol.introspect,
                'RevokeToken': self.oauth_protocol.revoke_token,
                'AuthorizeBadRedirectUri': self.oauth_protocol.authorize_bad_redirect_uri,
                'Consent': self.oauth_protocol.consent,

                # Additional Keycloak symbols (aliases)
                'INIT': self.oauth_protocol.authorize,
                'LOGIN_USER': self.oauth_protocol.login,
                'USER_AUTHORIZE': self.oauth_protocol.auth_code_redirect,
                'TOKEN_REQUEST': self.oauth_protocol.token_exchange,
                'RESOURCE_REQUEST': self.oauth_protocol.userinfo,

                # PKCE variants
                'AuthorizePKCES256': self.oauth_protocol.authorize_pkce_s256,
                'AuthorizePKCEPlain': self.oauth_protocol.authorize_pkce_plain,
                'AuthorizePKCEMethodConfusion': self.oauth_protocol.authorize_pkce_method_confusion,

                # Generic edge-case attack symbols (cross-target)
                'TokenExchangeXML': self.oauth_protocol.token_exchange_xml,
                'TokenExchangeNullContentType': self.oauth_protocol.token_exchange_null_content_type,
                'TokenExchangeParamFlood': self.oauth_protocol.token_exchange_param_flood,
                'UserInfoJWTAlgNone': self.oauth_protocol.user_info_jwt_alg_none,
                'UserInfoJWTExpired': self.oauth_protocol.user_info_jwt_expired,
                'UserInfoJWTWrongSig': self.oauth_protocol.user_info_jwt_wrong_sig,
                'IntrospectEmptyToken': self.oauth_protocol.introspect_empty_token,
                'IntrospectMalformed': self.oauth_protocol.introspect_malformed,
                'AuthorizeParamFlood100': self.oauth_protocol.authorize_param_flood_100,

                # Device & Logout
                'DeviceAuthorization': self.oauth_protocol.device_authorize,
                'Logout': self.oauth_protocol.logout,

                # Implicit & Hybrid flows
                'AuthorizeImplicit': self.oauth_protocol.authorize_implicit,
                'AuthorizeHybrid': self.oauth_protocol.authorize_hybrid,
                'AuthorizeHybridIDToken': self.oauth_protocol.authorize_hybrid_idtoken,

                # Open redirect & SSRF testing
                'AuthorizeOpenRedirect': self.oauth_protocol.authorize_open_redirect,
                'AuthorizeRedirectSSRF': self.oauth_protocol.authorize_redirect_ssrf,

                # Scope escalation testing
                'AuthorizeScopeEscalation': self.oauth_protocol.authorize_scope_escalation,
                'AuthorizeScopeAdmin': self.oauth_protocol.authorize_scope_admin,

                # Token confusion attacks
                'UseRefreshAsAccess': self.oauth_protocol.use_refresh_as_access,
                'UseIDTokenAsAccess': self.oauth_protocol.use_id_token_as_access,

                # PKCE downgrade & cross-client attacks
                'TokenExchangeNoPKCE': self.oauth_protocol.token_exchange_no_pkce,
                'TokenExchangeWrongClient': self.oauth_protocol.token_exchange_wrong_client,
                'TokenExchangeInvalidClient': self.oauth_protocol.token_exchange_invalid_client,
                'TokenExchangeValidClientWrongSecret': self.oauth_protocol.token_wrong_client_secret,

                # PAR (Pushed Authorization Request)
                'PushedAuthorizationRequest': self.oauth_protocol.pushed_authorization_request,
                'AuthorizePAR': self.oauth_protocol.authorize_par,

                # ====== AUTHELIA-SPECIFIC SYMBOLS ======
                'AutheliaAuthorize': self.oauth_protocol.authelia_authorize,
                'AutheliaLogin': self.oauth_protocol.authelia_login,
                'AutheliaAuthCodeRedirect': self.oauth_protocol.authelia_auth_code_redirect,
                'AutheliaFirstFactor': self.oauth_protocol.authelia_firstfactor,
                'AutheliaSecondFactor': self.oauth_protocol.authelia_secondfactor_totp,
                'AutheliaSecondFactorTOTP': self.oauth_protocol.authelia_secondfactor_totp,
                'AutheliaSecondFactorWebAuthn': self.oauth_protocol.authelia_secondfactor_webauthn,
                'AutheliaConsent': self.oauth_protocol.authelia_consent,
                'AutheliaLogout': self.oauth_protocol.authelia_logout,
                'AutheliaState': self.oauth_protocol.authelia_state,
                'AutheliaConfiguration': self.oauth_protocol.authelia_configuration,
                'AutheliaFirstFactorBypass': self.oauth_protocol.authelia_firstfactor_bypass,
                'Authelia2FABypass': self.oauth_protocol.authelia_2fa_bypass,
                'AutheliaConsentBypass': self.oauth_protocol.authelia_consent_bypass,
                'AutheliaRegulationBypass': self.oauth_protocol.authelia_regulation_bypass,
                'AutheliaSessionFixation': self.oauth_protocol.authelia_session_fixation,

                # ====== AUTHELIA AUDIT-PACK SYMBOLS (SECURITY_AUDIT.md §7) ======
                'AutheliaConsentIDFuzz': self.oauth_protocol.authelia_consent_id_fuzz,
                'AutheliaParFlood': self.oauth_protocol.authelia_par_flood,
                'AutheliaAuthorizeAfter1FA': self.oauth_protocol.authelia_authorize_after_1fa,
                'AutheliaConsentSubjectSwap': self.oauth_protocol.authelia_consent_subject_swap,
                'AutheliaSessionRegenCheck': self.oauth_protocol.authelia_session_regen_check,
                'AutheliaPKCEMethodConfusion': self.oauth_protocol.authelia_pkce_method_confusion,
                'AutheliaRedirectMismatchToken': self.oauth_protocol.authelia_redirect_mismatch_token,
                'AutheliaIntrospectCrossClient': self.oauth_protocol.authelia_introspect_cross_client,
                'AutheliaUserinfoAlgNone': self.oauth_protocol.authelia_userinfo_alg_none,
                'AutheliaForwardAuthSpoof': self.oauth_protocol.authelia_forward_auth_spoof,

                # ====== WSO2-SPECIFIC SYMBOLS ======
                'Wso2Authorize': self.oauth_protocol.wso2_authorize,
                'Wso2Login': self.oauth_protocol.wso2_login,
                'Wso2AuthCodeRedirect': self.oauth_protocol.wso2_auth_code_redirect,
                'Wso2Introspect': self.oauth_protocol.wso2_introspect,
                'Wso2DCRRegister': self.oauth_protocol.wso2_dcr_register,
                'Wso2SCIM2Users': self.oauth_protocol.wso2_scim2_users,
                'Wso2ConsentBypass': self.oauth_protocol.wso2_consent_bypass,
                'Wso2SessionKeyReplay': self.oauth_protocol.wso2_session_key_replay,
                'Wso2AdminAPI': self.oauth_protocol.wso2_admin_api,
                # NEW: deeper WSO2 state exploration
                'Wso2PromptNone': self.oauth_protocol.wso2_prompt_none,
                'Wso2RequestUriSSRF': self.oauth_protocol.wso2_request_uri_ssrf,
                'Wso2ScopeInjection': self.oauth_protocol.wso2_scope_injection,
                'Wso2AuthCodeReplay': self.oauth_protocol.wso2_auth_code_replay,
                'Wso2TenantConfusion': self.oauth_protocol.wso2_tenant_confusion,
                'Wso2DCRSqlInjection': self.oauth_protocol.wso2_dcr_sql_injection,

                # ====== CASDOOR-SPECIFIC SYMBOLS ======
                'CasdoorAuthorize': self.oauth_protocol.authorize,
                'CasdoorLogin': self.oauth_protocol.login,
                'CasdoorAuthCodeRedirect': self.oauth_protocol.auth_code_redirect,
                'CasdoorConsent': self.oauth_protocol.consent,
                'CasdoorAutoSigninPasswordInURL': self.oauth_protocol.casdoor_auto_signin_password_in_url,
                'CasdoorSessionCookieFlags': self.oauth_protocol.casdoor_session_cookie_flags,
                'CasdoorUserinfoCorsOpen': self.oauth_protocol.casdoor_userinfo_cors_open,
                'CasdoorTokenCorsOriginEcho': self.oauth_protocol.casdoor_token_cors_origin_echo,
                'CasdoorAuthCodeReplay': self.oauth_protocol.casdoor_auth_code_replay,

                # ====== ORY HYDRA-SPECIFIC SYMBOLS ======
                'HydraAuthorize': self.oauth_protocol.authorize,
                'HydraLogin': self.oauth_protocol.login,
                'HydraAuthCodeRedirect': self.oauth_protocol.auth_code_redirect,
                'HydraConsent': self.oauth_protocol.consent,
                'HydraAdminAPIProbe': self.oauth_protocol.hydra_admin_api_probe,
                'HydraClientCreation': self.oauth_protocol.hydra_client_creation_api,
                'HydraParFlood': self.oauth_protocol.hydra_par_flood,

                # ====== ZITADEL-SPECIFIC SYMBOLS ======
                'ZitadelAuthorize': self.oauth_protocol.authorize,
                'ZitadelLogin': self.oauth_protocol.login,
                'ZitadelAuthCodeRedirect': self.oauth_protocol.auth_code_redirect,
                'ZitadelConsent': self.oauth_protocol.consent,
                'ZitadelAPIProbe': self.oauth_protocol.zitadel_api_probe,
                'ZitadelMFABypass': self.oauth_protocol.zitadel_mfa_bypass,
                'ZitadelOrgContextConfusion': self.oauth_protocol.zitadel_org_context_confusion,
                'ZitadelTokenExchangeImpersonation': self.oauth_protocol.zitadel_token_exchange_impersonation,

                # ====== AUTHENTIK-SPECIFIC SYMBOLS ======
                'AuthentikAuthorize': self.oauth_protocol.authorize,
                'AuthentikLogin': self.oauth_protocol.login,
                'AuthentikAuthCodeRedirect': self.oauth_protocol.auth_code_redirect,
                'AuthentikFlowStageBypass': self.oauth_protocol.authentik_flow_stage_bypass,
                'AuthentikCSRFTokenReuse': self.oauth_protocol.authentik_csrf_token_reuse,
                'AuthentikDeviceCodeFuzz': self.oauth_protocol.authentik_device_code_fuzz,
                'AuthentikIntrospectCrossClient': self.oauth_protocol.authentik_introspect_cross_client,
                'AuthentikTokenConfusion': self.oauth_protocol.authentik_token_confusion,
                'AuthentikScopeEscalation': self.oauth_protocol.authentik_scope_escalation,
                'AuthentikEndSessionRedirect': self.oauth_protocol.authentik_end_session_redirect,

                # ====== SIMPLELOGIN-SPECIFIC SYMBOLS ======
                'SimpleLoginAuthorize': self.oauth_protocol.authorize,
                'SimpleLoginLogin': self.oauth_protocol.login,
                'SimpleLoginAuthCodeRedirect': self.oauth_protocol.auth_code_redirect,
                'SimpleLoginCSRFByass': self.oauth_protocol.simplelogin_csrf_bypass,
                'SimpleLoginOpenRedirect': self.oauth_protocol.simplelogin_open_redirect,
                'SimpleLoginTokenReplay': self.oauth_protocol.simplelogin_token_replay,
                'SimpleLoginScopeManipulation': self.oauth_protocol.simplelogin_scope_manipulation,
                'SimpleLoginClientImpersonation': self.oauth_protocol.simplelogin_client_impersonation,

                # node-oidc-provider symbols
                'NodeOIDCAuthorize': self.oauth_protocol.authorize,
                'NodeOIDCLogin': self.oauth_protocol.login,
                'NodeOIDCAuthCodeRedirect': self.oauth_protocol.auth_code_redirect,
                'NodeOIDCPKCEPlain': self.oauth_protocol.nodeoidc_pkce_plain,
                'NodeOIDCCodeReplay': self.oauth_protocol.nodeoidc_code_replay,
                'NodeOIDCInvalidVerifier': self.oauth_protocol.nodeoidc_invalid_code_verifier,
                'NodeOIDCIntrospectCrossClient': self.oauth_protocol.nodeoidc_introspection_cross_client,
                'NodeOIDCScopeEscalation': self.oauth_protocol.nodeoidc_scope_escalation,

                # ====== LOGTO-SPECIFIC SYMBOLS ======
                'LogtoPKCEPlain': self.oauth_protocol.logto_pkce_plain,
                'LogtoCodeReplay': self.oauth_protocol.logto_code_replay,
                'LogtoIntrospectCrossClient': self.oauth_protocol.logto_introspect_cross_client,
                'LogtoScopeEscalation': self.oauth_protocol.logto_scope_escalation,
                'LogtoContentTypeJSON': self.oauth_protocol.logto_content_type_json,

            }

            if actual_symbol in method_map:
                overrides = self.symbol_overrides.get(symbol, {}) if isinstance(self.symbol_overrides, dict) else {}

                # ---- WSO2 precondition guard -----------------------------
                # Login/AuthCodeRedirect are meaningful only after Authorize
                # produced a sessionDataKey. Running them on a broken flow
                # produces transport errors that cascade into SERVER_ERROR
                # false positives (see report.json 20/20 MEDIUM alerts).
                if self.target_type == 'wso2' and actual_symbol == 'Wso2Login':
                    sdk = getattr(self.oauth_protocol, '_wso2_session_data_key', None)
                    last_loc = getattr(self.oauth_protocol, 'last_location', '') or ''
                    if not sdk and 'error=' in last_loc:
                        self._last_response = None
                        return 'Skipped'
                # ----------------------------------------------------------

                response_type, response = method_map[actual_symbol](**overrides)
                # Cache the raw response so upstream oracles (e.g. the
                # open-redirect check in core/fuzzer.py) can inspect
                # headers without us having to change the step() return
                # contract that aalpy's SUL abstract class requires.
                try:
                    self._last_response = response
                except Exception:
                    pass
                if response.status_code == 200:
                    result = 'Success'
                elif response.status_code == 201:
                    result = 'Created'
                elif response.status_code == 302:
                    result = 'Redirect'
                elif response.status_code == 400:
                    result = 'BadRequest'
                elif response.status_code == 401:
                    result = 'Unauthorized'
                elif response.status_code == 403:
                    result = 'Forbidden'
                elif response.status_code == 404:
                    result = 'NotFound'
                elif response.status_code >= 500:
                    result = 'ServerError'
                else:
                    result = f'Status{response.status_code}'
                # Note: mutation details logging moved to fuzzer for consolidated output
                return result
            else:
                self._last_response = None
                return 'UnknownSymbol'
        except Exception as e:
            # Clear cached response on the exception path so the oracle
            # does not accidentally reuse a stale Response from a previous
            # successful symbol.
            self._last_response = None
            # Simplified error handling - suppress verbose connection errors
            code = 0
            error_msg = str(e)
            
            try:
                last = self.oauth_protocol.get_received_data()[-1]
                code = int(last.get('status_code', 0) or 0)
            except Exception:
                pass
            
            # Only log non-connection errors (connection timeouts are normal during fuzzing)
            if 'Max retries exceeded' not in error_msg and 'ConnectionError' not in type(e).__name__:
                error_brief = error_msg[:60] if error_msg else 'Unknown'
                print(f"  [ERR] {symbol}: {error_brief}")
            
            return f"Status{code}"
    
    def process_query(self, symbol: str) -> str:
        """Process single query symbol"""
        return self.step(symbol)
    
    def query(self, symbols: List[str]) -> List[str]:
        """Execute sequence of OAuth symbols"""
        # print(f'Current OAuth query: {symbols}')
        mutated_view = [
            s + ('[' + ','.join(self._mutation_tags(s)) + ']' if self._mutation_tags(s) else '')
            for s in symbols
        ]
        print(f'Current OAuth query: {mutated_view}')
        self.pre()
        
        results = []
        for symbol in symbols:
            result = self.step(symbol)
            results.append(result)
            tags = self._mutation_tags(symbol)
            mark = ('[' + ','.join(tags) + ']') if tags else ''
            print(f'{symbol}{mark} -> {result}')
        
        self.post()
        self.num_queries += 1
        self.num_steps += len(symbols)
        self.performed_steps_in_query = self.num_steps
        
        return results
    
    def fuzz_query(self, symbols: List[str]) -> Tuple[List[str], List[Dict], List[Dict]]:
        """
        Execute fuzzing query and return results with raw data
        Returns: (responses, sent_data, received_data)
        """
        if self.oauth_protocol is None:
            self.reset()
        
        responses = []
        for symbol in symbols:
            response = self.step(symbol)
            responses.append(response)
        
        # Get raw data for fuzzing analysis
        sent_data = self.oauth_protocol.get_sent_data()
        received_data = self.oauth_protocol.get_received_data()
        
        return responses, sent_data, received_data
    
    def get_raw_sent_bytes(self) -> bytes:
        """Get raw sent bytes for pyafl integration"""
        if self.oauth_protocol:
            return self.oauth_protocol.get_raw_sent_bytes()
        return b''
    
    def get_raw_received_bytes(self) -> bytes:
        """Get raw received bytes for pyafl integration"""
        if self.oauth_protocol:
            return self.oauth_protocol.get_raw_received_bytes()
        return b''
    
    def check_connection(self):
        """Check if target service is still running"""
        if self.target_process:
            retcode = self.target_process.poll()
            if retcode is None:
                pass
            else:
                pass
        else:
            pass
    
    def get_session_info(self) -> Dict[str, Any]:
        """Get current session information for debugging"""
        return {}
    
    def save_session_log(self, filename: str):
        """Save session log for debugging"""
        pass
