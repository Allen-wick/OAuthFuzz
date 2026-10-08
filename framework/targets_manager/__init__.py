#!/usr/bin/env python3
"""
targets_manager — unified Docker/JaCoCo lifecycle managers for all
OAuth / OIDC fuzzing targets.

Members:
  TargetManager      — abstract base class for all target managers
  KeycloakManager    — Keycloak (Java, JaCoCo)
  AutheliaManager    — Authelia (Go, Go native coverage)
  SpringAuthzManager — Spring Authorization Server (Java, JaCoCo)
  CxfOAuthManager    — Apache CXF rs-security-oauth2 (Java, JaCoCo)
  Wso2Manager        — WSO2 Identity Server (Java, JaCoCo)
  CasdoorManager     — Casdoor (Go, Go native coverage)
  OryHydraManager    — Ory Hydra (Go, Go native coverage)
  ZitadelManager     — Zitadel (Go, Go native coverage)
  GoCoverageManager  — Go native coverage helper (shared by all Go targets)
"""

from targets_manager.base import TargetManager
from targets_manager.keycloak_manager import KeycloakManager, create_test_realm
from targets_manager.authelia_manager import AutheliaManager, create_test_config_authelia
from targets_manager.spring_authz_manager import SpringAuthzManager, create_test_config_spring_authz
from targets_manager.cxf_oauth_manager import CxfOAuthManager, create_test_config_cxf
from targets_manager.wso2_manager import Wso2Manager, create_test_config_wso2
from targets_manager.casdoor_manager import CasdoorManager
from targets_manager.ory_hydra_manager import OryHydraManager
from targets_manager.zitadel_manager import ZitadelManager
from targets_manager.authentik_manager import AuthentikManager
from targets_manager.simplelogin_manager import SimpleLoginManager
from targets_manager.nodeoidc_manager import NodeOIDCManager
from targets_manager.logto_manager import LogtoManager
from targets_manager.go_coverage_manager import (
    GoCoverageManager, GoCoverageData,
    AutheliaErrorPatterns, CasdoorErrorPatterns,
    OryHydraErrorPatterns, ZitadelErrorPatterns,
    AuthentikErrorPatterns,
    SimpleLoginErrorPatterns,
    NodeOIDCErrorPatterns,
    LogtoErrorPatterns,
)

__all__ = [
    'TargetManager',
    'KeycloakManager', 'create_test_realm',
    'AutheliaManager', 'create_test_config_authelia',
    'SpringAuthzManager', 'create_test_config_spring_authz',
    'CxfOAuthManager', 'create_test_config_cxf',
    'Wso2Manager', 'create_test_config_wso2',
    'CasdoorManager',
    'OryHydraManager',
    'ZitadelManager',
    'AuthentikManager',
    'SimpleLoginManager',
    'NodeOIDCManager',
    'LogtoManager',
    'GoCoverageManager', 'GoCoverageData',
    'AutheliaErrorPatterns', 'CasdoorErrorPatterns',
    'OryHydraErrorPatterns', 'ZitadelErrorPatterns',
    'AuthentikErrorPatterns',
    'SimpleLoginErrorPatterns',
    'NodeOIDCErrorPatterns',
    'LogtoErrorPatterns',
]
