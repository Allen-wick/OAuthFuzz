#!/usr/bin/env python3
"""
OAuth/OIDC Protocol Implementation for Multi-Target Fuzzing
Backward-compatible shim — protocol methods now organized in protocol/ package.
"""

from core.config import OAuthConfig

from protocol.base import OAuthProtocolBase
from protocol.keycloak import KeycloakProtocolMixin
from protocol.authelia import AutheliaProtocolMixin
from protocol.casdoor import CasdoorProtocolMixin
from protocol.ory_hydra import OryHydraProtocolMixin
from protocol.zitadel import ZitadelProtocolMixin
from protocol.spring_authz import SpringAuthzProtocolMixin
from protocol.cxf_oauth import CxfOAuthProtocolMixin
from protocol.logto import LogtoProtocolMixin
from protocol.wso2 import Wso2ProtocolMixin
from protocol.shiro import ShiroProtocolMixin
from protocol.authentik import AuthentikProtocolMixin
from protocol.simplelogin import SimpleLoginProtocolMixin
from protocol.nodeoidc import NodeOIDCProtocolMixin
from protocol.attacks import AttackProtocolMixin


class OAuthProtocol(
    KeycloakProtocolMixin,
    AutheliaProtocolMixin,
    CasdoorProtocolMixin,
    OryHydraProtocolMixin,
    ZitadelProtocolMixin,
    AuthentikProtocolMixin,
    SimpleLoginProtocolMixin,
    NodeOIDCProtocolMixin,
    Wso2ProtocolMixin,
    SpringAuthzProtocolMixin,
    CxfOAuthProtocolMixin,
    LogtoProtocolMixin,
    ShiroProtocolMixin,
    AttackProtocolMixin,
    OAuthProtocolBase,
):
    """
    Unified OAuth/OIDC Protocol handler supporting:
      - Keycloak                  (target_type='keycloak')
      - Authelia                  (target_type='authelia')
      - Casdoor                   (target_type='casdoor')
      - Ory Hydra                 (target_type='ory_hydra')
      - Zitadel                   (target_type='zitadel')
      - Spring Authorization Server (target_type='spring_authz')
      - Apache CXF                (target_type='cxf_oauth')
      - WSO2 Identity Server      (target_type='wso2')
      - Logto                     (target_type='logto')
      - Apache Shiro              (target_type='shiro')
      - Authentik                 (target_type='authentik')
      - SimpleLogin               (target_type='simplelogin')
      - node-oidc-provider        (target_type='nodeoidc')
    """

    _OIDC_TARGETS = frozenset({'spring_authz', 'cxf_oauth', 'wso2', 'logto', 'shiro'})

    def _configure_endpoints(self):
        target = getattr(self.config, 'target_type', 'keycloak')
        if target == 'casdoor':
            return CasdoorProtocolMixin._configure_endpoints(self)
        if target == 'ory_hydra':
            return OryHydraProtocolMixin._configure_endpoints(self)
        if target == 'zitadel':
            return ZitadelProtocolMixin._configure_endpoints(self)
        if target == 'spring_authz':
            return SpringAuthzProtocolMixin._configure_endpoints(self)
        if target == 'cxf_oauth':
            return CxfOAuthProtocolMixin._configure_endpoints(self)
        if target == 'wso2':
            return Wso2ProtocolMixin._configure_endpoints(self)
        if target == 'logto':
            return LogtoProtocolMixin._configure_endpoints(self)
        if target == 'shiro':
            return ShiroProtocolMixin._configure_endpoints(self)
        if target == 'authentik':
            return AuthentikProtocolMixin._configure_endpoints(self)
        if target == 'simplelogin':
            return SimpleLoginProtocolMixin._configure_endpoints(self)
        if target == 'nodeoidc':
            return NodeOIDCProtocolMixin._configure_endpoints(self)
        if target == 'authelia':
            self.auth_endpoint = f"{self.config.base_url}/api/oidc/authorization"
            self.token_endpoint = f"{self.config.base_url}/api/oidc/token"
            self.userinfo_endpoint = f"{self.config.base_url}/api/oidc/userinfo"
            self.introspect_endpoint = f"{self.config.base_url}/api/oidc/introspection"
            self.revoke_endpoint = f"{self.config.base_url}/api/oidc/revocation"
            self.device_authorize_endpoint = None
        else:
            self.auth_endpoint = f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/auth"
            self.token_endpoint = f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/token"
            self.userinfo_endpoint = f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/userinfo"
            self.introspect_endpoint = f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/token/introspect"
            self.revoke_endpoint = f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/logout"
            self.device_authorize_endpoint = f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/device/auth"

    def authorize(self, **kwargs):
        target = getattr(self.config, 'target_type', 'keycloak')
        if target == 'casdoor':
            return CasdoorProtocolMixin.authorize(self, **kwargs)
        if target == 'ory_hydra':
            return OryHydraProtocolMixin.authorize(self, **kwargs)
        if target == 'zitadel':
            return ZitadelProtocolMixin.authorize(self, **kwargs)
        if target == 'wso2':
            return Wso2ProtocolMixin.wso2_authorize(self, **kwargs)
        if target == 'spring_authz':
            return SpringAuthzProtocolMixin.authorize(self, **kwargs)
        if target == 'cxf_oauth':
            return CxfOAuthProtocolMixin.authorize(self, **kwargs)
        if target == 'logto':
            return LogtoProtocolMixin.authorize(self, **kwargs)
        if target == 'shiro':
            return ShiroProtocolMixin.authorize(self, **kwargs)
        if target == 'authentik':
            return AuthentikProtocolMixin.authorize(self, **kwargs)
        if target == 'simplelogin':
            return SimpleLoginProtocolMixin.authorize(self, **kwargs)
        if target == 'nodeoidc':
            return NodeOIDCProtocolMixin.authorize(self, **kwargs)
        if target == 'authelia':
            return AutheliaProtocolMixin.authelia_authorize(self, **kwargs)
        return KeycloakProtocolMixin.authorize(self, **kwargs)

    def login(self, **kwargs):
        target = getattr(self.config, 'target_type', 'keycloak')
        if target == 'casdoor':
            return CasdoorProtocolMixin.login(self, **kwargs)
        if target == 'ory_hydra':
            return OryHydraProtocolMixin.login(self, **kwargs)
        if target == 'zitadel':
            return ZitadelProtocolMixin.login(self, **kwargs)
        if target == 'wso2':
            return Wso2ProtocolMixin.wso2_login(self, **kwargs)
        if target == 'spring_authz':
            return SpringAuthzProtocolMixin.login(self, **kwargs)
        if target == 'cxf_oauth':
            return CxfOAuthProtocolMixin.login(self, **kwargs)
        if target == 'logto':
            return LogtoProtocolMixin.login(self, **kwargs)
        if target == 'shiro':
            return ShiroProtocolMixin.login(self, **kwargs)
        if target == 'authentik':
            return AuthentikProtocolMixin.login(self, **kwargs)
        if target == 'simplelogin':
            return SimpleLoginProtocolMixin.login(self, **kwargs)
        if target == 'nodeoidc':
            return NodeOIDCProtocolMixin.login(self, **kwargs)
        if target == 'authelia':
            return AutheliaProtocolMixin.authelia_login(self, **kwargs)
        return KeycloakProtocolMixin.login(self, **kwargs)

    def auth_code_redirect(self, **kwargs):
        target = getattr(self.config, 'target_type', 'keycloak')
        if target == 'casdoor':
            return CasdoorProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'ory_hydra':
            return OryHydraProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'zitadel':
            return ZitadelProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'wso2':
            return Wso2ProtocolMixin.wso2_auth_code_redirect(self, **kwargs)
        if target == 'spring_authz':
            return SpringAuthzProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'cxf_oauth':
            return CxfOAuthProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'logto':
            return LogtoProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'shiro':
            return ShiroProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'authentik':
            return AuthentikProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'simplelogin':
            return SimpleLoginProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'nodeoidc':
            return NodeOIDCProtocolMixin.auth_code_redirect(self, **kwargs)
        if target == 'authelia':
            return AutheliaProtocolMixin.authelia_auth_code_redirect(self, **kwargs)
        return KeycloakProtocolMixin.auth_code_redirect(self, **kwargs)

    def token_exchange(self, **kwargs):
        target = getattr(self.config, 'target_type', 'keycloak')
        if target == 'cxf_oauth':
            self.code_verifier = None
        # Shiro supports PKCE, so keep code_verifier for Shiro targets
        return OAuthProtocolBase.token_exchange(self, **kwargs)


__all__ = ['OAuthConfig', 'OAuthProtocol']
