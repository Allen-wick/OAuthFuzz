#!/usr/bin/env python3
"""AFLNet-style protocol sequence fuzzer with coverage guidance."""

import os
import time
import random
import json
import re
from typing import Dict, List, Optional

from core.config import OAuthConfig
from core.coverage import CoverageData, GranularCoverageData, JaCoCoManager
from core.adapters import BoofuzzAdapter, SeleniumSULAdapter
from core.security import SecurityOracles, RaceConditionTester
from core.health import ServerHealthMonitor

class OAuthFuzzMinimalFuzzer:
    """
    Minimal OAuthFuzz protocol fuzzer:
    - Seeded by valid OAuth message sequences (symbols)
    - Sequence-level mutations
    - State feedback via response status sequence
    - Coverage-guided: keep sequences only if new coverage fingerprint increases
    - Multi-target support: Keycloak / Authelia / Spring AuthZ / CXF / WSO2
    """

    # ==============================================================
    # TARGET PROFILE REGISTRY
    # --------------------------------------------------------------
    # Each profile describes the protocol capabilities that affect
    # seed selection, mutation, and weight assignment. Profiles are
    # the single source of truth for "what does this target support".
    # ==============================================================
    _TARGET_PROFILES = {
        'keycloak': {
            'description': 'Keycloak (Java/JaCoCo). Full OIDC + PAR + Device + Implicit.',
            'supports_pkce': True,
            'pkce_required': False,
            'supports_userinfo': True,
            'supports_par': True,
            'supports_device': True,
            'supports_implicit': True,
            'supports_hybrid': True,
            'supports_password_grant': True,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': False,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': False,
            'unsupported_symbols': set(),
            'default_container_key': ('keycloak', 'container_name', 'keycloak-fuzz-coverage'),
        },
        'authelia': {
            'description': 'Authelia (Go). OIDC + mandatory 2FA + Authelia-specific APIs.',
            'supports_pkce': True,
            'pkce_required': True,  # Server enforces PKCE regardless of client config
            'supports_userinfo': True,
            'supports_par': True,
            'supports_device': True,  # Confirmed: discovery has device_authorization_endpoint + device_code grant
            'supports_implicit': True,  # Confirmed: response_types include id_token, token, id_token token
            'supports_hybrid': False,
            'supports_password_grant': False,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': False,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': True,
            'unsupported_symbols': {'PasswordGrant',
                                    'AuthorizeHybrid',
                                    'AuthorizeHybridIDToken'},
            'default_container_key': ('authelia', 'container_name', 'authelia-fuzz'),
        },
        'spring_authz': {
            'description': 'Spring Authorization Server (OAuth 2.1). PKCE mandatory.',
            'supports_pkce': True,
            'pkce_required': True,
            'supports_userinfo': True,
            'supports_par': True,
            'supports_device': True,
            'supports_implicit': True,
            'supports_hybrid': True,
            'supports_password_grant': False,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': False,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': False,
            'unsupported_symbols': set(),
            'default_container_key': ('spring_authz', 'container_name', 'sas-fuzz'),
        },
        'cxf_oauth': {
            'description': 'Apache CXF rs-security-oauth2 3.5.x. No UserInfo/PKCE/PAR/Implicit.',
            'supports_pkce': False,
            'pkce_required': False,
            'supports_userinfo': False,
            'supports_par': False,
            'supports_device': False,
            'supports_implicit': False,
            'supports_hybrid': False,
            'supports_password_grant': True,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': True,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': False,
            'unsupported_symbols': {
                'UserInfo', 'UserInfoWrongToken', 'UserInfoExpiredToken',
                'UserInfoWrongSig', 'UserInfoJWTAlgNone', 'UserInfoJWTExpired',
                'UserInfoJWTWrongSig', 'DeviceAuthorization', 'Logout',
                'AuthorizeImplicit', 'AuthorizeHybrid', 'AuthorizeHybridIDToken',
                'PushedAuthorizationRequest', 'AuthorizePAR',
                'AuthorizePKCES256', 'AuthorizePKCEPlain',
                'AuthorizePKCEMethodConfusion', 'TokenExchangeNoPKCE',
                'UseIDTokenAsAccess', 'Consent',
            },
            'default_container_key': ('cxf_oauth', 'container_name', 'cxf-oauth-fuzz'),
        },
        'wso2': {
            'description': 'WSO2 Identity Server. Full OIDC + PAR + Device + Implicit.',
            'supports_pkce': True,
            'pkce_required': False,
            'supports_userinfo': True,
            'supports_par': True,
            'supports_device': True,
            'supports_implicit': True,
            'supports_hybrid': True,
            'supports_password_grant': True,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': True,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': False,
            'unsupported_symbols': set(),
            'default_container_key': ('wso2', 'container_name', 'wso2is-fuzz'),
        },
        'casdoor': {
            'description': 'Casdoor (Go/Beego). OIDC + password grant + MFA. No PAR/Device/Implicit.',
            'supports_pkce': True,
            'pkce_required': False,
            'supports_userinfo': True,
            'supports_par': False,
            'supports_device': False,
            'supports_implicit': False,
            'supports_hybrid': False,
            'supports_password_grant': True,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': False,
            'supports_introspect': True,
            'supports_revoke': False,
            'supports_2fa': True,
            'unsupported_symbols': {'DeviceAuthorization', 'AuthorizeImplicit',
                                    'AuthorizeHybrid', 'AuthorizeHybridIDToken',
                                    'PushedAuthorizationRequest', 'AuthorizePAR',
                                    'RevokeToken', 'Logout'},
            'default_container_key': ('casdoor', 'container_name', 'casdoor-fuzz'),
        },
        'ory_hydra': {
            'description': 'Ory Hydra (Go). Certified OIDC + PAR + Admin API. No password grant.',
            'supports_pkce': True,
            'pkce_required': False,
            'supports_userinfo': True,
            'supports_par': True,
            'supports_device': False,
            'supports_implicit': True,
            'supports_hybrid': True,
            'supports_password_grant': False,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': False,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': False,
            'unsupported_symbols': {'PasswordGrant', 'DeviceAuthorization'},
            'default_container_key': ('ory_hydra', 'container_name', 'ory-hydra-fuzz'),
        },
        'zitadel': {
            'description': 'Zitadel (Go/gRPC). Full IAM + OIDC + MFA + multi-tenant + TokenExchange.',
            'supports_pkce': True,
            'pkce_required': False,
            'supports_userinfo': True,
            'supports_par': True,
            'supports_device': True,
            'supports_implicit': True,
            'supports_hybrid': True,
            'supports_password_grant': True,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': True,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': True,
            'unsupported_symbols': set(),
            'default_container_key': ('zitadel', 'container_name', 'zitadel-fuzz'),
        },
        'shiro': {
            'description': 'Apache Shiro 2.2.0 OAuth2 Server (Java/JaCoCo). PKCE required, auth code + client creds + password.',
            'supports_pkce': True,
            'pkce_required': True,
            'supports_userinfo': True,
            'supports_par': False,
            'supports_device': False,
            'supports_implicit': False,
            'supports_hybrid': False,
            'supports_password_grant': True,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': False,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': False,
            'unsupported_symbols': {
                'DeviceAuthorization', 'AuthorizeImplicit',
                'AuthorizeHybrid', 'AuthorizeHybridIDToken',
                'PushedAuthorizationRequest', 'AuthorizePAR',
                'Logout', 'Consent',
                'UserInfoJWTAlgNone', 'UserInfoJWTExpired', 'UserInfoJWTWrongSig',
            },
            'default_container_key': ('shiro', 'container_name', 'shiro-oauth-fuzz'),
        },
        'authentik': {
            'description': 'Authentik (Python/Django). Full OIDC + PKCE + Device + Introspection + Revocation + Django flow-based login.',
            'supports_pkce': True,
            'pkce_required': False,
            'supports_userinfo': True,
            'supports_par': False,
            'supports_device': True,
            'supports_implicit': True,
            'supports_hybrid': True,
            'supports_password_grant': False,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': False,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': False,
            'unsupported_symbols': {
                'PasswordGrant',
                'PushedAuthorizationRequest', 'AuthorizePAR',
            },
            'default_container_key': ('authentik', 'container_name', 'authentik-fuzz'),
        },
        'simplelogin': {
            'description': 'SimpleLogin (Python/Flask). Basic OAuth2 authorize+token+userinfo. No refresh/introspect/revoke.',
            'supports_pkce': True,
            'pkce_required': False,
            'supports_userinfo': True,
            'supports_par': False,
            'supports_device': False,
            'supports_implicit': False,
            'supports_hybrid': False,
            'supports_password_grant': False,
            'supports_client_credentials': False,
            'supports_refresh_token': False,
            'supports_jwt_bearer': False,
            'supports_introspect': False,
            'supports_revoke': False,
            'supports_2fa': False,
            'unsupported_symbols': {
                'PasswordGrant', 'PushedAuthorizationRequest', 'AuthorizePAR',
                'DeviceAuthorization', 'RefreshToken', 'Introspect', 'RevokeToken',
            },
            'default_container_key': ('simplelogin', 'container_name', 'simplelogin-fuzz'),
        },
        'nodeoidc': {
            'description': 'node-oidc-provider (Node.js). Full OIDC + PKCE(required) + Device + Introspection + Revocation.',
            'supports_pkce': True,
            'pkce_required': True,
            'supports_userinfo': True,
            'supports_par': False,
            'supports_device': True,
            'supports_implicit': True,
            'supports_hybrid': False,
            'supports_password_grant': False,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': False,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': False,
            'unsupported_symbols': {
                'PasswordGrant', 'AuthorizePAR',
                'AuthorizeHybrid', 'AuthorizeHybridIDToken',
            },
            'default_container_key': ('nodeoidc', 'container_name', 'node-oidc-fuzz'),
        },
        'logto': {
            'description': 'Logto (TypeScript/Node.js). Full OIDC + PKCE + PAR + Device + Introspect + Revoke.',
            'supports_pkce': True,
            'pkce_required': True,
            'supports_userinfo': True,
            'supports_par': True,
            'supports_device': True,
            'supports_implicit': False,
            'supports_hybrid': False,
            'supports_password_grant': False,
            'supports_client_credentials': True,
            'supports_refresh_token': True,
            'supports_jwt_bearer': False,
            'supports_introspect': True,
            'supports_revoke': True,
            'supports_2fa': False,
            'unsupported_symbols': {
                'PasswordGrant', 'AuthorizeImplicit',
                'AuthorizeHybrid', 'AuthorizeHybridIDToken',
            },
            'default_container_key': ('logto', 'container_name', 'logto-fuzz'),
        },
    }

    def __init__(self, config: Dict, jacoco_manager: Optional[JaCoCoManager] = None,
                 boofuzz_adapter: Optional[BoofuzzAdapter] = None,
                 selenium_adapter: Optional[SeleniumSULAdapter] = None):
        from OAuthMapper.OAuthSUT import OAuthSUT
        self.config = config or {}
        oauth_cfg = self.config.get('oauth', {})

        # ---- Step 1: Target detection ----
        self.target_type = self.config.get('target_type', 'keycloak').lower()
        if self.target_type == 'java_based':
            self.target_type = 'keycloak'
        # Fall back to keycloak profile if target is unknown (backward compat)
        if self.target_type not in self._TARGET_PROFILES:
            print(f"[Fuzzer] Unknown target_type '{self.target_type}', "
                  f"falling back to 'keycloak' profile")
            self.target_type = 'keycloak'
        self.profile = self._TARGET_PROFILES[self.target_type]

        # ---- Step 2: OAuth client config (target-aware) ----
        self.oauth_config = OAuthConfig(
            base_url=oauth_cfg.get('base_url', 'http://127.0.0.1:8080'),
            realm=oauth_cfg.get('realm', 'fuzz') if self.target_type == 'keycloak' else '',
            client_id=oauth_cfg.get('client_id', 'fuzz-client'),
            client_secret=oauth_cfg.get('client_secret', 'fuzz-client-secret'),
            redirect_uri=oauth_cfg.get('redirect_uri', 'http://127.0.0.1:7777/callback'),
            username=oauth_cfg.get('user', 'testuser'),
            password=oauth_cfg.get('password', 'testpass'),
            scope=oauth_cfg.get('scope', 'openid profile email'),
            target_type=self.target_type
        )
        self.sut = OAuthSUT(self.oauth_config, target_type=self.target_type)

        # ---- Step 3: Protocol endpoint configuration (dispatcher) ----
        self._configure_endpoints()

        self.jacoco = jacoco_manager
        self.boofuzz = boofuzz_adapter
        self.selenium = selenium_adapter

        # Target managers
        self.kc_manager = self.config.get('_kc_manager')
        self.authelia_manager = self.config.get('_authelia_manager')
        self.generic_manager = self.config.get('_target_manager')

        # Select active manager
        if self.target_type == 'authelia':
            self.target_manager = self.authelia_manager
        elif self.target_type in ('spring_authz', 'cxf_oauth', 'wso2', 'logto', 'nodeoidc'):
            self.target_manager = self.generic_manager
        elif self.target_type in ('casdoor', 'ory_hydra', 'zitadel'):
            self.target_manager = self.generic_manager
        elif self.target_type == 'shiro':
            self.target_manager = self.config.get('_target_manager')
        else:
            self.target_manager = self.kc_manager

        self.dump_interval = self.config.get('jacoco', {}).get('dump_every_n', 10)
        if self.target_type == 'wso2' and self.dump_interval > 25:
            self.dump_interval = 25
        self.no_gain_rounds = 0

        # ---- Step 4: Server health monitor (target-aware via profile) ----
        section, key, default = self.profile['default_container_key']
        container_name = self.config.get(section, {}).get(key, default)
        self.health_monitor = ServerHealthMonitor(container_name)

        # Coverage data (JaCoCo for Keycloak, state-based for Authelia)
        self.baseline_coverage = GranularCoverageData()
        self.current_coverage = GranularCoverageData()

        # Go coverage manager placeholder (injected from run_oauth_fuzzing.py)
        self.go_coverage = None

        self.corpus: List[List[str]] = []
        self.seen_state_signatures: set = set()
        self.selection_weights: List[float] = []

        # === AFLnet-style coverage-guided fuzzing state ===
        self.favored_flags: List[bool] = []
        self._global_probe_set: set = set()
        self._template_counts: Dict[Tuple, int] = {}
        self._iterations_since_baseline_refresh: int = 0
        self._baseline_refresh_every: int = int(
            self.config.get('fuzzing', {}).get('baseline_refresh_every', 25)
        )
        self._coverage_cache_ts: float = 0.0
        self._coverage_cache_ttl: float = float(
            self.config.get('fuzzing', {}).get('coverage_cache_ttl', 15.0)
        )
        self._stagnant_probe_rounds: int = 0
        self._use_differential_dump: bool = bool(
            self.config.get('fuzzing', {}).get('differential_coverage', True)
        )

        self._save_interesting_cases: bool = bool(
            self.config.get('fuzzing', {}).get('save_interesting_cases', False)
        )
        self._budget_protocol_steps: int = int(
            self.config.get('fuzzing', {}).get('budget_protocol_steps', 0) or 0
        )

        # --- CS-revision ablation switches (2026-09) --------------------
        # disable_ep: Endpoint Profiling off — generic RFC 6749 seed corpus,
        #   uniform initial weights, no capability-based symbol scrubbing.
        #   The CVE-pattern tables are profiling output, hence also off.
        # disable_cve_patterns: historical-CVE mutation knowledge off —
        #   attack value tables, target-specific attack symbols/payloads,
        #   D.1–D.5 wire mutations, JWT algorithm-confusion variants.
        #   RFC-derived structure-preserving mutation stays on.
        # disable_feedback: Dynamic Guidance off — round-robin seed
        #   selection, frozen corpus (no interesting-promotion), no
        #   weight updates, no baseline rotation. Detection still runs.
        self._disable_ep: bool = bool(
            self.config.get('fuzzing', {}).get('disable_ep', False)
        )
        self._disable_cve_patterns: bool = bool(
            self.config.get('fuzzing', {}).get('disable_cve_patterns', False)
        ) or self._disable_ep
        self._disable_feedback: bool = bool(
            self.config.get('fuzzing', {}).get('disable_feedback', False)
        )
        self._rr_counter: int = 0
        if self.boofuzz is not None:
            self.boofuzz._cve_disabled = self._disable_cve_patterns

        self.execution_count = 0
        self.mutation_count = 0
        self.interesting_cases: List[Dict] = []

        # ---- Step 5: Seed corpus + weights (target-specific) ----
        self._load_seed_sequences()

    # ==================================================================
    # ENDPOINT CONFIGURATION — one method per target, dispatcher below
    # ==================================================================
    def _configure_endpoints(self):
        """Dispatcher: wire protocol endpoints for the active target."""
        configurator = {
            'keycloak':    self._configure_keycloak_endpoints,
            'authelia':    self._configure_authelia_endpoints,
            'spring_authz': self._configure_spring_authz_endpoints,
            'cxf_oauth':   self._configure_cxf_oauth_endpoints,
            'wso2':        self._configure_wso2_endpoints,
            'casdoor':     self._configure_casdoor_endpoints,
            'ory_hydra':   self._configure_ory_hydra_endpoints,
            'zitadel':     self._configure_zitadel_endpoints,
            'shiro':       self._configure_shiro_endpoints,
            'authentik':   self._configure_authentik_endpoints,
            'simplelogin': self._configure_simplelogin_endpoints,
            'nodeoidc':    self._configure_nodeoidc_endpoints,
            'logto':       self._configure_logto_endpoints,
        }.get(self.target_type)
        if configurator:
            try:
                configurator()
            except Exception as e:
                print(f"[Fuzzer] Endpoint configuration for "
                      f"'{self.target_type}' failed: {e}")

    def _configure_keycloak_endpoints(self):
        """Keycloak realm-based endpoint layout — relies on OAuthSUT defaults."""
        # OAuthSUT already builds Keycloak endpoints from (base_url, realm).
        # Nothing to override here; the method exists for symmetry + future hooks.
        return

    def _configure_authelia_endpoints(self):
        """Authelia OIDC endpoints + 2FA-specific API surface."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        proto.auth_endpoint = f"{base_url}/api/oidc/authorization"
        proto.token_endpoint = f"{base_url}/api/oidc/token"
        proto.userinfo_endpoint = f"{base_url}/api/oidc/userinfo"
        proto.introspect_endpoint = f"{base_url}/api/oidc/introspection"
        proto.revoke_endpoint = f"{base_url}/api/oidc/revocation"
        proto.firstfactor_endpoint = f"{base_url}/api/firstfactor"
        proto.secondfactor_totp_endpoint = f"{base_url}/api/secondfactor/totp"
        proto.secondfactor_webauthn_endpoint = f"{base_url}/api/secondfactor/webauthn"
        proto.logout_endpoint = f"{base_url}/api/logout"
        proto.state_endpoint = f"{base_url}/api/state"
        proto.configuration_endpoint = f"{base_url}/api/configuration"
        proto.consent_endpoint = f"{base_url}/api/oidc/consent"
        self._authelia_endpoints = {
            'authorization': proto.auth_endpoint,
            'token': proto.token_endpoint,
            'userinfo': proto.userinfo_endpoint,
            'introspection': proto.introspect_endpoint,
            'revocation': proto.revoke_endpoint,
            'firstfactor': proto.firstfactor_endpoint,
            'secondfactor_totp': proto.secondfactor_totp_endpoint,
            'secondfactor_webauthn': proto.secondfactor_webauthn_endpoint,
            'logout': proto.logout_endpoint,
            'state': proto.state_endpoint,
            'consent': proto.consent_endpoint,
        }

    def _configure_spring_authz_endpoints(self):
        """Spring Authorization Server default endpoint layout (RFC 8414 style)."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        proto.auth_endpoint = f"{base_url}/oauth2/authorize"
        proto.token_endpoint = f"{base_url}/oauth2/token"
        proto.userinfo_endpoint = f"{base_url}/userinfo"
        proto.introspect_endpoint = f"{base_url}/oauth2/introspect"
        proto.revoke_endpoint = f"{base_url}/oauth2/revoke"
        proto.jwks_endpoint = f"{base_url}/oauth2/jwks"
        proto.par_endpoint = f"{base_url}/oauth2/par"
        proto.device_endpoint = f"{base_url}/oauth2/device_authorization"

    def _configure_cxf_oauth_endpoints(self):
        """Apache CXF rs-security-oauth2 /services/oauth2/* layout."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        proto.auth_endpoint = f"{base_url}/services/oauth2/authorize"
        proto.token_endpoint = f"{base_url}/services/oauth2/token"
        proto.introspect_endpoint = f"{base_url}/services/oauth2/introspect"
        proto.revoke_endpoint = f"{base_url}/services/oauth2/revoke"
        # CXF does NOT mount /userinfo in the rs-security-oauth2 sample.
        # Clear it so the SUT emits clean errors instead of baking 404s into coverage.
        proto.userinfo_endpoint = None

    def _configure_wso2_endpoints(self):
        """WSO2 Identity Server /oauth2/* layout + auth endpoints."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        # Attempt OIDC discovery — WSO2 IS 7.x publishes at
        # /oauth2/oidcdiscovery/.well-known/openid-configuration
        discovered = {}
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            discovery_url = f"{base_url}/oauth2/oidcdiscovery/.well-known/openid-configuration"
            r = requests.get(discovery_url, timeout=5,
                             headers={'Accept': 'application/json'},
                             verify=False)
            if r.status_code == 200:
                discovered = r.json()
                print(f"[WSO2] OIDC Discovery ✓ {discovery_url}")
        except Exception as e:
            print(f"[WSO2] OIDC Discovery fallback (reason: {e})")

        proto.auth_endpoint       = discovered.get('authorization_endpoint',       f"{base_url}/oauth2/authorize")
        proto.token_endpoint      = discovered.get('token_endpoint',               f"{base_url}/oauth2/token")
        proto.userinfo_endpoint   = discovered.get('userinfo_endpoint',            f"{base_url}/oauth2/userinfo")
        proto.introspect_endpoint = discovered.get('introspection_endpoint',       f"{base_url}/oauth2/introspect")
        proto.revoke_endpoint     = discovered.get('revocation_endpoint',          f"{base_url}/oauth2/revoke")
        proto.jwks_endpoint       = discovered.get('jwks_uri',                     f"{base_url}/oauth2/jwks")
        proto.par_endpoint        = discovered.get('pushed_authorization_request_endpoint', f"{base_url}/oauth2/par")
        proto.device_endpoint     = discovered.get('device_authorization_endpoint', f"{base_url}/oauth2/device_authorize")
        # WSO2-specific authentication endpoints (not in OIDC discovery)
        proto._wso2_login_endpoint = f"{base_url}/authenticationendpoint/login.do"
        proto._wso2_commonauth_endpoint = f"{base_url}/commonauth"
        proto._wso2_consent_endpoint = f"{base_url}/authenticationendpoint/oauth2_consent.do"
        proto._wso2_dcr_endpoint  = f"{base_url}/api/identity/oauth2/dcr/v1.1/register"
        proto._wso2_scim2_endpoint = f"{base_url}/scim2/Users"

    def _configure_casdoor_endpoints(self):
        """Casdoor /api/login/oauth/* endpoint layout."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        proto.auth_endpoint = f"{base_url}/api/login/oauth/authorize"
        proto.token_endpoint = f"{base_url}/api/login/oauth/access_token"
        proto.userinfo_endpoint = f"{base_url}/api/userinfo"
        proto.introspect_endpoint = f"{base_url}/api/login/oauth/introspect"
        proto.jwks_endpoint = f"{base_url}/.well-known/jwks"
        proto.discovery_url = f"{base_url}/.well-known/openid-configuration"
        proto._casdoor_auto_signin_url = f"{base_url}/api/auto-signin"

    def _configure_ory_hydra_endpoints(self):
        """Ory Hydra /oauth2/* endpoint layout."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
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
        """Zitadel /oauth/v2/* endpoint layout."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
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

    def _configure_shiro_endpoints(self):
        """Apache Shiro /oauth2/* endpoint layout (matches ShiroOAuthServer)."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        proto.auth_endpoint = f"{base_url}/oauth2/authorize"
        proto.token_endpoint = f"{base_url}/oauth2/token"
        proto.userinfo_endpoint = f"{base_url}/oauth2/userinfo"
        proto.introspect_endpoint = f"{base_url}/oauth2/introspect"
        proto.revoke_endpoint = f"{base_url}/oauth2/revoke"
        proto.jwks_endpoint = f"{base_url}/oauth2/jwks"
        proto.discovery_url = f"{base_url}/.well-known/openid-configuration"
        # Shiro-specific: login page for auth code flow
        proto._shiro_login_endpoint = f"{base_url}/login"

    def _configure_authentik_endpoints(self):
        """Authentik /application/o/* endpoint layout."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        proto.auth_endpoint = f"{base_url}/application/o/authorize/"
        proto.token_endpoint = f"{base_url}/application/o/token/"
        proto.userinfo_endpoint = f"{base_url}/application/o/userinfo/"
        proto.introspect_endpoint = f"{base_url}/application/o/introspect/"
        proto.revoke_endpoint = f"{base_url}/application/o/revoke/"
        proto.end_session_endpoint = f"{base_url}/application/o/end-session/"
        proto.device_endpoint = f"{base_url}/application/o/device/"
        proto.discovery_url = f"{base_url}/.well-known/openid-configuration"
        proto._authentik_login_url = f"{base_url}/flows/default-authentication/"

    def _configure_simplelogin_endpoints(self):
        """SimpleLogin /oauth2/* endpoint layout."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        proto.auth_endpoint = f"{base_url}/oauth2/authorize"
        proto.token_endpoint = f"{base_url}/oauth2/token"
        proto.userinfo_endpoint = f"{base_url}/oauth2/userinfo"
        proto.introspect_endpoint = None
        proto.revoke_endpoint = None
        proto.end_session_endpoint = None
        proto.device_endpoint = None

    def _configure_nodeoidc_endpoints(self):
        """node-oidc-provider /oidc/* endpoint layout."""
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        # base_url already includes /oidc prefix
        proto.auth_endpoint = f"{base_url}/auth"
        proto.token_endpoint = f"{base_url}/token"
        proto.userinfo_endpoint = f"{base_url}/me"
        proto.introspect_endpoint = f"{base_url}/token/introspection"
        proto.revoke_endpoint = f"{base_url}/token/revocation"
        proto.jwks_endpoint = f"{base_url}/jwks"
        proto.device_endpoint = f"{base_url}/device/auth"
        proto.end_session_endpoint = f"{base_url}/session/end"
        self._nodeoidc_endpoints = {
            'authorization': proto.auth_endpoint,
            'token': proto.token_endpoint,
            'userinfo': proto.userinfo_endpoint,
            'introspection': proto.introspect_endpoint,
            'revocation': proto.revoke_endpoint,
            'jwks': proto.jwks_endpoint,
            'device': proto.device_endpoint,
            'end_session': proto.end_session_endpoint,
        }

    def _configure_logto_endpoints(self):
        """Logto /oidc/* endpoint layout (port 3001 default).

        Logto 1.40 serves userinfo at /oidc/me, introspection at
        /oidc/token/introspection, and revocation at /oidc/token/revocation.
        """
        base_url = self.oauth_config.base_url
        if not (hasattr(self.sut, 'proto') and self.sut.oauth_protocol):
            return
        proto = self.sut.oauth_protocol
        proto.auth_endpoint = f"{base_url}/oidc/auth"
        proto.token_endpoint = f"{base_url}/oidc/token"
        proto.userinfo_endpoint = f"{base_url}/oidc/me"
        proto.introspect_endpoint = f"{base_url}/oidc/token/introspection"
        proto.revoke_endpoint = f"{base_url}/oidc/token/revocation"
        proto.jwks_endpoint = f"{base_url}/oidc/jwks"
        proto.par_endpoint = f"{base_url}/oidc/request"
        proto.device_endpoint = f"{base_url}/oidc/device/auth"
        proto.end_session_endpoint = f"{base_url}/oidc/session/end"
        self._logto_endpoints = {
            'authorization': proto.auth_endpoint,
            'token': proto.token_endpoint,
            'userinfo': proto.userinfo_endpoint,
            'introspection': proto.introspect_endpoint,
            'revocation': proto.revoke_endpoint,
            'jwks': proto.jwks_endpoint,
            'par': proto.par_endpoint,
            'device': proto.device_endpoint,
            'end_session': proto.end_session_endpoint,
        }

    # ================================================================
    # END endpoint configurators
    # ================================================================

    def _get_coverage_data(self) -> GranularCoverageData:
        """Return the most authoritative current coverage snapshot.

        Always returns the max of (baseline, current) to guarantee monotonic
        reporting — prevents agent-reset races from surfacing regressions.
        """
        if (self.current_coverage and
                self.current_coverage.instructions_covered >
                self.baseline_coverage.instructions_covered):
            self.baseline_coverage = self.current_coverage
        return self.baseline_coverage
    
    def _get_state_based_coverage(self) -> GranularCoverageData:
        """
        Get coverage for Authelia (Go) targets via GoCoverageManager.
        This method delegates entirely to GoCoverageManager.collect_coverage()
        which handles real Go coverage and state-based fallback internally.
        """
        go_cov = getattr(self, 'go_coverage', None)
        if go_cov is None:
            mgr = getattr(self, 'authelia_manager', None) or getattr(self, 'target_manager', None)
            if mgr:
                go_cov = getattr(mgr, 'go_coverage', None)

        coverage = GranularCoverageData()
        if go_cov:
            try:
                go_data = go_cov.collect_coverage()
                if go_data:
                    coverage.instructions_covered = go_data.instructions_covered
                    coverage.instructions_total = go_data.instructions_total
                    coverage.lines_covered = go_data.lines_covered
                    coverage.lines_total = go_data.lines_total
                    coverage.coverage_percentage = go_data.coverage_percentage
                    coverage.module_coverage = go_data.module_coverage or {}
                    coverage.branches_covered = go_data.branches_covered
                    coverage.branches_total = go_data.branches_total
            except Exception as e:
                print(f"[GoCoverage] State coverage error: {e}")
        return coverage

    def _check_security_anomaly(self, symbol: str, result: str) -> Optional[Dict]:
        """Check if a successful result on a security-sensitive symbol indicates a vulnerability."""
        # Critical: operations that should NEVER succeed with wrong credentials/tokens
        critical_patterns = [
            ('UserInfoWrongToken', 'AUTH_BYPASS', 'UserInfo accepted invalid token'),
            ('TokenWrongClientSecret', 'CLIENT_AUTH_BYPASS', 'Token endpoint accepted wrong client secret'),
            ('TokenBadCode', 'CODE_VALIDATION_BYPASS', 'Token endpoint accepted invalid auth code'),
            ('RefreshTokenWrongSecret', 'REFRESH_AUTH_BYPASS', 'Refresh with wrong client secret succeeded'),
            ('RevokeTokenWrongSecret', 'REVOCATION_BYPASS', 'Revoke with wrong client secret succeeded'),
            ('IntrospectWrongSecret', 'INTROSPECTION_BYPASS', 'Introspection with wrong secret succeeded'),
            # ===== AUTHELIA AUDIT-PACK CRITICAL =====
            ('AutheliaForwardAuthSpoof', 'FORWARD_AUTH_BYPASS', 'Forward-auth verify trusted spoofed X-Forwarded-* headers'),
            ('AutheliaIntrospectCrossClient', 'INTROSPECTION_CROSS_CLIENT', 'Introspection returned active=true for foreign client token'),
            ('AutheliaRedirectMismatchToken', 'REDIRECT_URI_BYPASS', 'Token issued with redirect_uri differing from authorize-time'),
            ('AutheliaSessionRegenCheck', 'SESSION_FIXATION', 'Pre-auth cookie retained authenticated state after login'),
            # ===== CASDOOR AUDIT-PACK CRITICAL =====
            ('CasdoorAutoSigninPasswordInURL', 'PASSWORD_IN_URL', 'AutoSigninFilter accepted password in GET query parameter'),
            ('CasdoorAuthCodeReplay', 'CODE_REPLAY', 'Authorization code accepted more than once'),
            # ===== ORY HYDRA AUDIT-PACK CRITICAL =====
            ('HydraAdminAPIProbe', 'ADMIN_API_ACCESS', 'Admin API accessible without authentication'),
            # ===== ZITADEL AUDIT-PACK CRITICAL =====
            ('ZitadelOrgContextConfusion', 'ORG_ISOLATION_BYPASS', 'Organization context isolation bypassed'),
            ('ZitadelMFABypass', 'MFA_BYPASS', 'MFA management endpoints accessible without authentication'),
            # ===== AUTHENTIK AUDIT-PACK CRITICAL =====
            ('AuthentikFlowStageBypass', 'AUTH_BYPASS', 'Authentik flow stage bypassed — authentication skipped'),
            ('AuthentikCSRFTokenReuse', 'CSRF_BYPASS', 'CSRF token reused across sessions'),
            ('AuthentikTokenConfusion', 'TOKEN_CONFUSION', 'Token type confusion — wrong token type accepted'),
            # ===== SIMPLELOGIN AUDIT-PACK CRITICAL =====
            ('SimpleLoginCSRFByass', 'CSRF_BYPASS', 'SimpleLogin CSRF protection bypassed'),
            ('SimpleLoginTokenReplay', 'CODE_REPLAY', 'Authorization code or token replay succeeded'),
            ('SimpleLoginClientImpersonation', 'CLIENT_IMPERSONATION', 'Client impersonation succeeded'),
            # ===== NODE-OIDC-PROVIDER AUDIT-PACK CRITICAL =====
            ('NodeOIDCCodeReplay', 'CODE_REPLAY', 'Authorization code accepted more than once'),
            # ===== LOGTO AUDIT-PACK CRITICAL =====
            ('LogtoCodeReplay', 'CODE_REPLAY', 'Logto authorization code replay succeeded'),
        ]
        
        # NEW: Detect wrong_secret token exchange success (potential client_secret bypass)
        if 'wrong_secret' in symbol and 'TokenExchange' in symbol and result in ('Success', 'Created'):
            if self._is_real_success_response():
                return {
                    'type': 'CLIENT_SECRET_BYPASS',
                    'detail': f'Token exchange succeeded with wrong client secret: {symbol}',
                    'severity': 'CRITICAL',
                    'symbol': symbol,
                    'result': result
                }
        
        for pattern_sym, vuln_type, detail in critical_patterns:
            if pattern_sym in symbol and result in ('Success', 'Created'):
                if self._is_real_success_response():
                    return {
                        'type': vuln_type,
                        'detail': detail,
                        'severity': 'CRITICAL',
                        'symbol': symbol,
                        'result': result
                    }
        
        # High: scope escalation or missing PKCE
        high_patterns = [
            ('AuthorizeNoPKCE', 'PKCE_NOT_ENFORCED', 'Authorization succeeded without PKCE'),
            ('TokenExchange[scope_mutation', 'SCOPE_ESCALATION', 'Token granted with mutated scope'),
            # ===== AUTHELIA AUDIT-PACK HIGH =====
            ('AutheliaConsentSubjectSwap', 'CONSENT_SUBJECT_SWAP', 'Consent POST accepted attacker-supplied subject'),
            ('AutheliaPKCEMethodConfusion', 'PKCE_METHOD_CONFUSION', 'Token issued with code_verifier==challenge under plain method'),
            ('AutheliaUserinfoAlgNone', 'USERINFO_ALG_NONE', 'UserInfo returned application/jwt with alg:none header'),
            ('AutheliaAuthorizeAfter1FA', 'TWO_FACTOR_BYPASS', 'OIDC authorize granted code at 1FA-only session'),
            # ===== CASDOOR AUDIT-PACK HIGH =====
            ('CasdoorTokenCorsOriginEcho', 'CORS_ORIGIN_ECHO', 'CORS echoes origin with credentials on token endpoint'),
            ('CasdoorUserinfoCorsOpen', 'CORS_OPEN', 'UserInfo CORS accessible from arbitrary origin'),
            # ===== ORY HYDRA AUDIT-PACK HIGH =====
            ('HydraClientCreation', 'DYNAMIC_CLIENT_REGISTRATION', 'Dynamic client registration without authentication'),
            # ===== ZITADEL AUDIT-PACK HIGH =====
            ('ZitadelTokenExchangeImpersonation', 'TOKEN_EXCHANGE_IMPERSONATION', 'Token exchange impersonation across audiences'),
            ('ZitadelAPIProbe', 'API_ACCESS', 'Management/admin API probe returned sensitive data'),
            # ===== AUTHENTIK AUDIT-PACK HIGH =====
            ('AuthentikIntrospectCrossClient', 'INTROSPECTION_CROSS_CLIENT', 'Introspection returned active=true for foreign client token'),
            ('AuthentikScopeEscalation', 'SCOPE_ESCALATION', 'Token granted with escalated scope beyond authorization'),
            ('AuthentikDeviceCodeFuzz', 'DEVICE_CODE_BYPASS', 'Device code flow bypass or manipulation succeeded'),
            ('AuthentikEndSessionRedirect', 'OPEN_REDIRECT', 'End session endpoint redirected to unvalidated URL'),
            # ===== SIMPLELOGIN AUDIT-PACK HIGH =====
            ('SimpleLoginOpenRedirect', 'OPEN_REDIRECT', 'SimpleLogin open redirect vulnerability'),
            ('SimpleLoginScopeManipulation', 'SCOPE_ESCALATION', 'Scope manipulation yielded elevated privileges'),
            # ===== NODE-OIDC-PROVIDER AUDIT-PACK HIGH =====
            ('NodeOIDCPKCEPlain', 'PKCE_DOWNGRADE', 'PKCE plain method accepted (S256 required)'),
            ('NodeOIDCInvalidVerifier', 'PKCE_BYPASS', 'Invalid code_verifier accepted'),
            ('NodeOIDCIntrospectCrossClient', 'INTROSPECTION_CROSS_CLIENT', 'Cross-client introspection revealed token details'),
            ('NodeOIDCScopeEscalation', 'SCOPE_ESCALATION', 'Token granted with scope beyond authorization'),
            # ===== LOGTO AUDIT-PACK HIGH =====
            ('LogtoPKCEPlain', 'PKCE_DOWNGRADE', 'Logto accepted PKCE plain method (S256 required)'),
            ('LogtoIntrospectCrossClient', 'INTROSPECTION_CROSS_CLIENT', 'Logto cross-client introspection revealed token details'),
            ('LogtoScopeEscalation', 'SCOPE_ESCALATION', 'Logto token granted with escalated scope'),
            ('LogtoContentTypeJSON', 'CONTENT_TYPE_CONFUSION', 'Token endpoint accepted application/json body'),
        ]
        
        for pattern_sym, vuln_type, detail in high_patterns:
            if pattern_sym in symbol and result in ('Success', 'Created', 'Redirect'):
                return {
                    'type': vuln_type,
                    'detail': detail,
                    'severity': 'HIGH',
                    'symbol': symbol,
                    'result': result
                }

        # PKCE enforcement check — only alert once per session
        # (suppressed under the legacy-Oracle toggle: OAuth 2.0 core does not
        # require PKCE — see security.py pkce_enforcement_check)
        import os as _os
        if 'NoPKCE' in symbol and result in ('Success', 'Redirect') \
                and _os.environ.get('OAUTH_FUZZ_ORACLE_LEGACY') != '1':
            if not getattr(self, '_pkce_not_enforced_reported', False):
                self._pkce_not_enforced_reported = True
                return {
                    'type': 'PKCE_NOT_ENFORCED',
                    'detail': 'Authorization succeeded without PKCE',
                    'severity': 'HIGH',
                    'symbol': symbol,
                    'result': result
                }
        return None

    def _is_real_success_response(self) -> bool:
        """Check if the last SUT response is a genuine success, not a 200 with OAuth error body."""
        try:
            if self.sut and self.sut.oauth_protocol and self.sut.oauth_protocol.received_data:
                last_resp = self.sut.oauth_protocol.received_data[-1]
                body = ''
                content_type = ''
                if hasattr(last_resp, 'text'):
                    body = last_resp.text or ''
                    content_type = last_resp.headers.get('Content-Type', '') if hasattr(last_resp, 'headers') else ''
                elif isinstance(last_resp, dict):
                    body = str(last_resp.get('body', ''))
                    content_type = str(last_resp.get('headers', {}).get('Content-Type', ''))
                
                # Reject HTML responses — OAuth token endpoints return JSON
                if 'text/html' in content_type or body.strip().startswith('<!') or '<html' in body.lower()[:200]:
                    return False
                
                if '"error"' in body or '"error_description"' in body:
                    return False
                if body.strip().startswith('{'):
                    try:
                        data = json.loads(body)
                        if 'error' in data:
                            return False
                        if 'access_token' not in data and 'sub' not in data and 'username' not in data:
                            return False
                    except (json.JSONDecodeError, ValueError):
                        return False
                elif body.strip():
                    return False
        except Exception:
            pass
        return True

    def _check_redirect_security(self, symbol: str, result: str, response=None) -> Optional[Dict]:
        """Check if a redirect response indicates an open redirect vulnerability.

        Requires actual evidence: the Location header must point off the
        registered callback domain AND the URL must NOT contain a WSO2
        defensive marker (oauth2_error.do, error=invalid_request, etc.).
        """
        redirect_vuln_symbols = [
            'AuthorizeBadRedirectUri',
            'AuthorizeRedirectSSRF',
            'AuthorizeRedirectOpenRedirect',
        ]
        if not any(s in symbol for s in redirect_vuln_symbols):
            return None
        if response is None:
            return None

        loc = response.headers.get('Location', '')
        if not loc:
            return None

        # WSO2 / generic defensive responses — these are CORRECT behavior.
        defensive_markers = (
            'oauth2_error.do', 'authenticationendpoint/oauth2_error',
            'error=invalid_request', 'error=invalid_callback',
            'error=invalid_redirect_uri', 'oauthErrorCode=',
        )
        loc_l = loc.lower()
        if any(m in loc_l for m in defensive_markers):
            return None

        try:
            registered_host = urllib.parse.urlparse(
                self.config.get('oauth', {}).get(
                    'redirect_uri', 'http://127.0.0.1:7777/callback')).hostname
        except Exception:
            registered_host = '127.0.0.1'

        try:
            target_host = urllib.parse.urlparse(loc).hostname
        except Exception:
            target_host = None

        if target_host and target_host != registered_host:
            return {
                'type': 'OPEN_REDIRECT',
                'detail': f'Redirect to off-domain host {target_host} from {symbol}',
                'severity': 'HIGH',
                'symbol': symbol,
                'result': result,
                'location': loc[:300],
            }
        return None

    def _check_unusual_status(self, symbol: str, result: str) -> Optional[Dict]:
        """Check for unusual status codes that might indicate server errors or information disclosure."""
        # Transport-class results are not server bugs — silence them at the
        # oracle so a mis-classified synthetic-500 never escalates to MEDIUM.
        if result in ('Status0', 'UnknownSymbol'):
            return None

        # Server errors (only genuine 5xx responses, not synthesized ones)
        if result == 'ServerError' or re.match(r'^Status5\d\d$', result):
            # Suppress the well-known FP: Login invoked after Authorize
            # failed to produce a sessionDataKey. The synthetic-500 is a
            # cascaded fuzzer artefact, not a WSO2 bug.
            if symbol in ('Login', 'Wso2Login'):
                last_resp = getattr(self.sut, '_last_response', None)
                body = getattr(last_resp, 'text', '') or ''
                if ('no sessionDataKey' in body
                        or 'precondition' in body.lower()
                        or 'connection error' in body.lower()):
                    return None
            return {
                'type': 'SERVER_ERROR',
                'detail': f'Server error detected for {symbol}: {result}',
                'severity': 'MEDIUM',
                'symbol': symbol,
                'result': result,
            }

        if result in ('NotFound', '404') and symbol in ('Authorize', 'TokenExchange', 'UserInfo'):
            _expected_absent = self._get_unsupported_symbols()
            if symbol not in _expected_absent:
                return {
                    'type': 'ENDPOINT_CONFUSION',
                    'detail': f'Auth endpoint returned 404: {symbol}',
                    'severity': 'LOW',
                    'symbol': symbol,
                    'result': result,
                }

        return None

    def _log_security_alert(self, alert: Dict, go_cov=None) -> None:
        """Log a security alert with appropriate formatting."""
        severity = alert.get('severity', 'INFO')
        alert_type = alert.get('type', 'UNKNOWN')
        detail = alert.get('detail', '')

        # Map severity to emoji
        emoji_map = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': 'ℹ️'
        }
        emoji = emoji_map.get(severity, '⚠️')

        print(f"      {emoji} [{severity}] {alert_type}: {detail}")

    # ==================================================================
    # SEED CORPUS — dispatcher + one loader + one weight applier per target
    # ==================================================================
    # EP-off ablation corpus: plain RFC 6749 flows only — no per-target
    # capability knowledge, no CVE-inspired attack sequences.
    _GENERIC_SEED_CORPUS = [
        ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
        ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
        ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect'],
        ['PasswordGrant', 'UserInfo'],
        ['ClientCredentials'],
        ['RefreshToken'],
        ['Introspect'],
        ['RevokeToken'],
    ]

    def _get_unsupported_symbols(self) -> set:
        """Return symbols the current target does not support.

        Used during mutation to filter out steps that would produce guaranteed
        404s or protocol errors on this target, so the fuzzer does not spend
        its budget on dead endpoints.
        """
        if self._disable_ep:
            # EP-off arm: no capability matrix available.
            return set()
        return set(self.profile.get('unsupported_symbols') or set())

    def _scrub_unsupported(self, sequences: List[List[str]]) -> List[List[str]]:
        """Filter unsupported symbols from a list of sequences."""
        unsupported = self._get_unsupported_symbols()
        if not unsupported:
            return sequences
        scrubbed = []
        for seq in sequences:
            cleaned = [s for s in seq if s not in unsupported]
            if cleaned:
                scrubbed.append(cleaned)
        return scrubbed

    def _load_seed_sequences(self):
        """Thin dispatcher: load per-target seeds, apply per-target weights.

        Each target OWNS its corpus — no shared baseline. This guarantees that
        every seed sequence references only endpoints the target actually
        exposes, maximizing per-iteration coverage value.
        """
        # 0) EP-off ablation arm: generic corpus, uniform weights, no scrub.
        if self._disable_ep:
            self.corpus = [list(s) for s in self._GENERIC_SEED_CORPUS]
            self.favored_flags = [False] * len(self.corpus)
            self.selection_weights = [1.0] * len(self.corpus)
            return

        # 1) Seed loading
        loader = {
            'keycloak':    self._load_keycloak_seeds,
            'authelia':    self._load_authelia_seeds,
            'spring_authz': self._load_spring_authz_seeds,
            'cxf_oauth':   self._load_cxf_oauth_seeds,
            'wso2':        self._load_wso2_seeds,
            'casdoor':     self._load_casdoor_seeds,
            'ory_hydra':   self._load_ory_hydra_seeds,
            'zitadel':     self._load_zitadel_seeds,
            'shiro':       self._load_shiro_seeds,
            'authentik':   self._load_authentik_seeds,
            'simplelogin': self._load_simplelogin_seeds,
            'nodeoidc':    self._load_nodeoidc_seeds,
            'logto':       self._load_logto_seeds,
        }.get(self.target_type, self._load_keycloak_seeds)
        loader()

        # 2) Scrub any unsupported symbols that might have slipped through
        #    (also protects against future shared seed borrowing).
        self.corpus = self._scrub_unsupported(self.corpus)

        # 3) Initialize flags/weights
        self.favored_flags = [False] * len(self.corpus)
        self.selection_weights = [1.0] * len(self.corpus)

        # 4) Weight application
        weighter = {
            'keycloak':    self._apply_keycloak_weights,
            'authelia':    self._apply_authelia_weights,
            'spring_authz': self._apply_spring_authz_weights,
            'cxf_oauth':   self._apply_cxf_weights,
            'wso2':        self._apply_wso2_weights,
            'casdoor':     self._apply_casdoor_weights,
            'ory_hydra':   self._apply_ory_hydra_weights,
            'zitadel':     self._apply_zitadel_weights,
            'shiro':       self._apply_shiro_weights,
            'authentik':   self._apply_authentik_weights,
            'simplelogin': self._apply_simplelogin_weights,
            'nodeoidc':    self._apply_nodeoidc_weights,
            'logto':       self._apply_logto_weights,
        }.get(self.target_type, self._apply_keycloak_weights)
        try:
            weighter()
        except Exception as e:
            print(f"[Fuzzer] Weight application for '{self.target_type}' failed: {e}")

    def _bump_weight(self, seq: List[str], weight: float) -> None:
        """Shared helper: set the selection weight for an exact sequence."""
        try:
            idx = self.corpus.index(seq)
            if 0 <= idx < len(self.selection_weights):
                self.selection_weights[idx] = weight
        except (ValueError, IndexError):
            pass

    # ============================ KEYCLOAK ============================
    def _load_keycloak_seeds(self):
        """Keycloak baseline corpus — full OIDC + CVE-inspired attack sequences.

        Keycloak supports every OAuth 2.0/OIDC feature: auth_code+PKCE,
        password, client_credentials, refresh, device, PAR, implicit, hybrid,
        introspect, revoke, userinfo, logout, JWKS.
        """
        self.corpus = [
            # ── Core OIDC success flows ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect'],
            ['PasswordGrant', 'UserInfo'],
            ['ClientCredentials'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['DeviceAuthorization'],
            ['Logout'],
            # ── Core error paths (redirect/code/secret validation) ──
            ['AuthorizeBadRedirectUri'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenBadCode'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenWrongClientSecret'],
            ['UserInfoWrongToken'],
            # ── State-logic & replay ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'],
            ['PasswordGrant', 'RefreshToken', 'RefreshToken'],
            ['Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['Authorize', 'AuthCodeRedirect', 'TokenExchange'],
            ['PasswordGrant', 'RevokeToken', 'UserInfo'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken'],
            # ── Implicit / Hybrid (should usually be rejected) ──
            ['AuthorizeImplicit'],
            ['AuthorizeHybrid', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['AuthorizeHybridIDToken', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # ── Token-confusion attacks ──
            ['PasswordGrant', 'UseRefreshAsAccess'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'],
            # ── Scope escalation ──
            ['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # ── Open redirect / SSRF ──
            ['AuthorizeOpenRedirect', 'Login'],
            ['AuthorizeRedirectSSRF'],
            # ── PKCE attacks ──
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # ── Cross-client / enumeration ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
            ['TokenExchangeInvalidClient', 'TokenExchangeValidClientWrongSecret'],
            # ── PAR ──
            ['PushedAuthorizationRequest', 'AuthorizePAR', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # ── Introspect edge cases ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'IntrospectEmptyToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'IntrospectMalformed'],
            # ── UserInfo JWT attacks ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfoExpiredToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfoWrongSig'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfoJWTAlgNone'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfoJWTExpired'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfoJWTWrongSig'],
            # ── Content-type manipulation ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeXML'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeNullContentType'],
            # ── Parameter flooding ──
            ['AuthorizeParamFlood100', 'Login'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeParamFlood'],
            # ── Introspect+Revoke round-trip ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect', 'RevokeToken', 'Introspect'],
        ]

    def _apply_keycloak_weights(self):
        b = self._bump_weight
        # Coverage anchors
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.0)
        b(['PasswordGrant', 'UserInfo'], 1.8)
        b(['ClientCredentials'], 1.6)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'], 1.8)
        # Security-critical replay / state
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'], 2.5)
        b(['PasswordGrant', 'RefreshToken', 'RefreshToken'], 2.3)
        b(['Login', 'AuthCodeRedirect', 'TokenExchange'], 2.2)
        b(['PasswordGrant', 'RevokeToken', 'UserInfo'], 2.2)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken'], 2.0)
        # Attack classes
        b(['AuthorizeImplicit'], 2.0)
        b(['PasswordGrant', 'UseRefreshAsAccess'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'], 2.3)
        b(['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)
        b(['AuthorizeOpenRedirect', 'Login'], 2.5)
        b(['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'], 2.3)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'], 2.5)
        b(['AuthorizeHybrid', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 1.5)
        b(['AuthorizeHybridIDToken', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 1.5)
        b(['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 1.8)
        b(['PushedAuthorizationRequest', 'AuthorizePAR', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 1.4)
        b(['TokenExchangeInvalidClient', 'TokenExchangeValidClientWrongSecret'], 1.6)

    # ============================ AUTHELIA ============================
    def _load_authelia_seeds(self):
        """Authelia: OIDC core + 2FA attack sequences.

        Authelia enforces 2FA via /api/firstfactor + /api/secondfactor/*.
        Password grant is NOT supported.
        """
        oidc_core = [
            # Core OIDC (via Authelia-specific auth flow)
            ['AutheliaAuthorize', 'AutheliaLogin', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AutheliaAuthorize', 'AutheliaFirstFactor', 'AuthCodeRedirect', 'TokenExchange'],
            ['ClientCredentials'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['AuthorizeBadRedirectUri'],
            ['AuthorizeOpenRedirect', 'Login'],
            ['AuthorizeRedirectSSRF'],
            # Introspect / Revoke
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'IntrospectEmptyToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'IntrospectMalformed'],
        ]
        authelia_specific = [
            # First-factor flows
            ['AutheliaFirstFactor', 'AutheliaConsent', 'AuthCodeRedirect', 'TokenExchange'],
            ['AutheliaFirstFactor', 'TokenExchange'],
            # 2FA BYPASS (CRITICAL)
            ['AutheliaFirstFactor', 'AuthCodeRedirect'],
            ['AutheliaFirstFactor', 'AutheliaSecondFactor', 'AutheliaSecondFactor'],
            ['AutheliaFirstFactor', 'AutheliaSecondFactorNull'],
            ['AutheliaFirstFactor'] + ['AutheliaSecondFactorInvalid'] * 10,
            # Session attacks
            ['AutheliaFirstFactor', 'AutheliaLogout', 'AutheliaFirstFactor'],
            ['AutheliaFirstFactor', 'AutheliaConsent', 'AutheliaLogout', 'TokenExchange'],
            ['AutheliaFirstFactor', 'AutheliaSessionHijack'],
            # Consent bypass
            ['Authorize', 'AutheliaFirstFactor', 'TokenExchange'],
            ['AutheliaFirstFactor', 'AutheliaConsent', 'AutheliaConsent'],
            ['AutheliaFirstFactor', 'AutheliaConsentManipulated'],
            # State manipulation
            ['AutheliaState', 'Authorize', 'Login'],
            ['AutheliaStateNull', 'Login'],
            # Regulation / rate-limiting bypass
            ['AutheliaFirstFactor'] * 15,
            ['AutheliaFirstFactorBypass'] * 20,
            # Config probing
            ['AutheliaConfiguration', 'AutheliaState', 'AutheliaJWKS'],
            ['AutheliaDiscovery', 'AutheliaJWKS'],
            # Full 2FA flow
            ['Authorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor',
             'AutheliaConsent', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            # Refresh after logout
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'AutheliaLogout', 'RefreshToken'],
            # ===== AUDIT-PACK SEQUENCES (SECURITY_AUDIT.md §7) =====
            # B2/S2 — forged consent_id at consent POST
            ['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaConsentIDFuzz'],
            ['AutheliaConsentIDFuzz'],
            # B1/B3 — PAR oversize / nested request JWT
            ['AutheliaParFlood'],
            ['AutheliaParFlood', 'AutheliaAuthorize'],
            # S1/S4 — authorize after only 1FA (must require 2FA)
            ['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaAuthorizeAfter1FA', 'AuthCodeRedirect', 'TokenExchange'],
            # S3 — subject swap on consent POST
            ['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AutheliaConsentSubjectSwap'],
            # S4/E1 — session fixation (pre-auth cookie replay)
            ['AutheliaSessionRegenCheck'],
            ['AutheliaAuthorize', 'AutheliaSessionRegenCheck'],
            # S5 — PKCE method confusion (plain == challenge)
            ['AutheliaPKCEMethodConfusion', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AuthCodeRedirect', 'TokenExchange'],
            # M2 — redirect_uri mismatch at token exchange
            ['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AuthCodeRedirect', 'AutheliaRedirectMismatchToken'],
            # M3/M4 — cross-client introspection / userinfo
            ['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AuthCodeRedirect', 'TokenExchange', 'AutheliaIntrospectCrossClient'],
            ['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AuthCodeRedirect', 'TokenExchange', 'AutheliaUserinfoAlgNone'],
            # E3 — forward-auth header spoofing (no session needed)
            ['AutheliaForwardAuthSpoof'],
            ['AutheliaForwardAuthSpoof', 'AutheliaForwardAuthSpoof'],
            ['AutheliaAuthorize', 'AutheliaForwardAuthSpoof'],
        ]
        self.corpus = oidc_core + authelia_specific

    def _apply_authelia_weights(self):
        b = self._bump_weight
        # 2FA bypass — highest priority (CRITICAL attack class)
        b(['AutheliaFirstFactor', 'AuthCodeRedirect'], 3.0)
        b(['Authorize', 'AutheliaFirstFactor', 'TokenExchange'], 2.8)
        b(['AutheliaFirstFactor', 'AutheliaLogout', 'AutheliaFirstFactor'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
           'AutheliaLogout', 'RefreshToken'], 2.5)
        # Authentication core
        b(['AutheliaFirstFactor', 'AutheliaConsent', 'AuthCodeRedirect', 'TokenExchange'], 2.0)
        b(['Authorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor',
           'AutheliaConsent', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 1.8)
        b(['AutheliaFirstFactor', 'AutheliaSecondFactor', 'AutheliaSecondFactor'], 2.0)
        b(['AutheliaFirstFactor', 'AutheliaConsent', 'AutheliaLogout', 'TokenExchange'], 2.2)
        b(['AutheliaConfiguration', 'AutheliaState', 'AutheliaJWKS'], 1.5)
        b(['AutheliaState', 'Authorize', 'Login'], 1.6)
        # ===== AUDIT-PACK weights (SECURITY_AUDIT.md §7) =====
        b(['AutheliaForwardAuthSpoof'], 3.0)                              # E3 — highest-impact, zero-session
        b(['AutheliaSessionRegenCheck'], 2.8)                             # S4/E1 fixation
        b(['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaAuthorizeAfter1FA', 'AuthCodeRedirect', 'TokenExchange'], 2.7)
        b(['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AutheliaConsentSubjectSwap'], 2.5)
        b(['AutheliaPKCEMethodConfusion', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AuthCodeRedirect', 'TokenExchange'], 2.4)
        b(['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AuthCodeRedirect', 'AutheliaRedirectMismatchToken'], 2.4)
        b(['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AuthCodeRedirect', 'TokenExchange', 'AutheliaIntrospectCrossClient'], 2.2)
        b(['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaSecondFactor', 'AuthCodeRedirect', 'TokenExchange', 'AutheliaUserinfoAlgNone'], 2.0)
        b(['AutheliaParFlood'], 1.8)                                      # B1/B3 DoS surface
        b(['AutheliaAuthorize', 'AutheliaFirstFactor', 'AutheliaConsentIDFuzz'], 1.6)

    # =========================== SPRING AUTHZ ==========================
    def _load_spring_authz_seeds(self):
        """Spring Authorization Server (OAuth 2.1). PKCE mandatory.

        SAS supports: auth_code+PKCE (required), client_credentials, refresh,
        device_authorization, PAR, introspect, revoke, userinfo.
        Password grant is rejected by default → exercises error path.
        """
        self.corpus = [
            # Core success paths
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['ClientCredentials'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'],
            ['PasswordGrant'],  # rejected by SAS default — exercises error path
            # PKCE enforcement (CVE-2024-38819)
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Auth-code reuse (CVE-2024-38827)
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'],
            ['PasswordGrant', 'RefreshToken', 'RefreshToken'],
            ['Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Redirect URI validation
            ['AuthorizeBadRedirectUri'],
            ['AuthorizeOpenRedirect', 'Login'],
            ['AuthorizeRedirectSSRF'],
            # Introspection / Revocation
            ['PasswordGrant', 'RevokeToken', 'UserInfo'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'IntrospectEmptyToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'IntrospectMalformed'],
            # Token confusion
            ['PasswordGrant', 'UseRefreshAsAccess'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'],
            # Scope escalation
            ['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Cross-client / enumeration
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
            ['TokenExchangeInvalidClient', 'TokenExchangeValidClientWrongSecret'],
            # JWT attacks
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            
            # PAR (RFC 9126)
            ['PushedAuthorizationRequest', 'AuthorizePAR', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Implicit / Hybrid
            ['AuthorizeImplicit'],
            ['AuthorizeHybrid', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['AuthorizeHybridIDToken', 'Login', 'AuthCodeRedirect', 'TokenExchange']
        ]

    def _apply_spring_authz_weights(self):
        b = self._bump_weight
        # PKCE enforcement is the signature attack class for SAS
        b(['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'], 3.0)
        b(['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        # Auth-code reuse
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'], 3.0)
        b(['PasswordGrant', 'RefreshToken', 'RefreshToken'], 2.5)
        b(['Login', 'AuthCodeRedirect', 'TokenExchange'], 2.3)
        # Coverage anchors
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.2)
        b(['ClientCredentials'], 1.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'], 2.2)
        # Attack classes
        b(['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)
        b(['AuthorizeOpenRedirect', 'Login'], 2.5)
        b(['AuthorizeBadRedirectUri'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'], 2.5)
        b(['PasswordGrant', 'UseRefreshAsAccess'], 2.5)

    # ============================== CXF ==============================
    def _load_cxf_oauth_seeds(self):
        """Apache CXF rs-security-oauth2 3.5.x corpus.

        Deployed endpoints:
            /services/oauth2/authorize   (AuthorizationCodeGrantService)
            /services/oauth2/token       (AccessTokenService — 5 grant handlers)
            /services/oauth2/introspect  (TokenIntrospectionService)
            /services/oauth2/revoke      (TokenRevocationService)

        NOT available: /userinfo, /par, /device, Implicit/Hybrid.
        PKCE: not supported in CXF 3.5.x — sending code_challenge fails.
        Grants: authorization_code, password, client_credentials,
                refresh_token, urn:ietf:params:oauth:grant-type:jwt-bearer.
        """
        self.corpus = [
            # ── Core success flows (coverage baseline) ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['PasswordGrant'],
            ['ClientCredentials'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'],
            ['PasswordGrant', 'RevokeToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'],
            # ── Auth-code replay ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'],
            ['PasswordGrant', 'RefreshToken', 'RefreshToken'],
            # ── Ordering / skip ──
            ['Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['Authorize', 'AuthCodeRedirect', 'TokenExchange'],
            # ── Redirect URI validation (CXF CVE-2022-46364 class) ──
            ['AuthorizeBadRedirectUri'],
            ['AuthorizeOpenRedirect', 'Login'],
            ['AuthorizeRedirectSSRF'],
            # ── Client-auth attacks ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenWrongClientSecret'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenBadCode'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
            ['TokenExchangeInvalidClient', 'TokenExchangeValidClientWrongSecret'],
            # ── Token confusion ──
            ['PasswordGrant', 'UseRefreshAsAccess'],
            # ── Scope escalation ──
            ['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # ── Revocation correctness ──
            ['PasswordGrant', 'RevokeToken', 'Introspect'],
            ['PasswordGrant', 'RevokeToken', 'RevokeToken'],
            # ── Refresh-token chains ──
            ['PasswordGrant', 'RefreshToken', 'RefreshToken', 'RefreshToken'],
            ['PasswordGrant', 'RevokeToken', 'RefreshToken'],
            # ── Introspect edge cases ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'IntrospectEmptyToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'IntrospectMalformed'],
            # ── Content-Type manipulation ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeXML'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeNullContentType'],
            # ── Parameter flooding ──
            ['AuthorizeParamFlood100', 'Login'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeParamFlood'],
            # ── Multi-grant chained flows (handler routing) ──
            ['PasswordGrant', 'ClientCredentials', 'RefreshToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'PasswordGrant'],
            # --- Round 2 new findings (C45-C49) ---
            # C45: JCache isExpired unit mismatch — use expired refresh token
            ["PasswordGrant", "TokenExchange", "RefreshToken", "TokenExchange"],
            # C46: JCache no TTL — access stale tokens after long run
            ["ClientCredentials", "TokenExchange", "TokenExchange"],
            # C47: Validation cache DoS — rapid introspect flood
            ["ClientCredentials", "TokenExchange", "Introspect", "Introspect"],
            # C49: JSON injection via introspect
            ["ClientCredentials", "TokenExchange", "Introspect"],
        ]

    def _apply_cxf_weights(self):
        b = self._bump_weight
        # Core coverage anchors
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        b(['PasswordGrant'], 2.5)
        b(['ClientCredentials'], 2.0)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'], 2.0)
        b(['PasswordGrant', 'RevokeToken'], 2.0)
        # Auth-code replay
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'], 3.0)
        b(['PasswordGrant', 'RefreshToken', 'RefreshToken'], 2.5)
        # Redirect URI bypass (CXF CVE-2022-46364 class)
        b(['AuthorizeBadRedirectUri'], 2.8)
        b(['AuthorizeOpenRedirect', 'Login'], 2.8)
        b(['AuthorizeRedirectSSRF'], 2.5)
        # Client-auth bypass
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenWrongClientSecret'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'], 2.5)
        # Scope escalation
        b(['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)
        # Revocation correctness
        b(['PasswordGrant', 'RevokeToken', 'Introspect'], 2.5)
        b(['PasswordGrant', 'RevokeToken', 'RefreshToken'], 2.5)
        # Round 2 new findings weights
        b(['PasswordGrant', 'TokenExchange', 'RefreshToken', 'TokenExchange'], 2.5)  # C45 CRITICAL - expired RT never expires
        b(['ClientCredentials', 'TokenExchange', 'Introspect', 'Introspect'], 2.0)    # C47/C49 - cache DoS + JSON injection

    # ============================== WSO2 =============================
    def _load_wso2_seeds(self):
        """WSO2 Identity Server. Full OIDC + PAR + Device + WSO2-specific."""
        self.corpus = [
            # Core success (WSO2-specific flow)
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['PasswordGrant', 'UserInfo'],
            ['ClientCredentials'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'],
            # PKCE attacks
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Replay / state
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'],
            ['PasswordGrant', 'RefreshToken', 'RefreshToken'],
            ['Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Redirect URI
            ['AuthorizeBadRedirectUri'],
            ['AuthorizeOpenRedirect', 'Login'],
            ['AuthorizeRedirectSSRF'],
            # Introspect / Revoke (WSO2 requires Basic auth for introspect)
            ['PasswordGrant', 'RevokeToken', 'UserInfo'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'],
            # Token confusion
            ['PasswordGrant', 'UseRefreshAsAccess'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'],
            # Scope escalation
            ['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Cross-client / enumeration
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
            ['TokenExchangeInvalidClient', 'TokenExchangeValidClientWrongSecret'],
            # WSO2-specific: sessionDataKey replay
            ['Authorize', 'Login', 'Wso2SessionKeyReplay'],
            # WSO2-specific: consent bypass
            ['Authorize', 'Wso2ConsentBypass', 'TokenExchange'],
            # WSO2-specific: DCR fuzzing
            ['Wso2DCRRegister'],
            # WSO2-specific: SCIM2 user enumeration
            ['Wso2SCIM2Users'],
            # WSO2-specific: admin API access
            ['Wso2AdminAPI'],
            # JWT attacks
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfoJWTAlgNone'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfoJWTExpired'],
            # Content-Type
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeXML'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeNullContentType'],
            # Parameter flooding
            ['AuthorizeParamFlood100', 'Login'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeParamFlood'],
            # PAR / Device / Implicit / Hybrid
            ['PushedAuthorizationRequest', 'AuthorizePAR', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['DeviceAuthorization'],
            ['AuthorizeImplicit'],
            ['AuthorizeHybrid', 'Login', 'AuthCodeRedirect', 'TokenExchange'],

            # ========== NEW: deeper WSO2 state exploration ==========
            # prompt=none silent-auth branch (must be rejected without session)
            ['Wso2PromptNone'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Wso2PromptNone'],
            # RFC 9101 request_uri SSRF
            ['Wso2RequestUriSSRF'],
            ['Wso2RequestUriSSRF', 'Login', 'AuthCodeRedirect'],
            # Scope-parameter edge cases (regex DoS, SQLi, smuggling)
            ['Wso2ScopeInjection', 'Login', 'AuthCodeRedirect'],
            ['Wso2ScopeInjection', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Auth-code reuse after a successful exchange (MUST fail)
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Wso2AuthCodeReplay'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'Wso2AuthCodeReplay', 'Wso2AuthCodeReplay'],
            # Multi-tenant path resolver confusion
            ['Wso2TenantConfusion'],
            ['Wso2TenantConfusion', 'Login'],
            # DCR stored-SQLi probe
            ['Wso2DCRSqlInjection'],
            ['Wso2DCRSqlInjection', 'Wso2SCIM2Users'],
            # Deep state chains mixing new + existing symbols
            ['Authorize', 'Login', 'AuthCodeRedirect', 'Wso2SessionKeyReplay'],
            ['Wso2DCRRegister', 'Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['PushedAuthorizationRequest', 'Wso2ScopeInjection', 'Login', 'AuthCodeRedirect'],
            # Concurrent-session probes (same sequence of logins back-to-back)
            ['Authorize', 'Login', 'AuthCodeRedirect', 'Authorize', 'Login', 'AuthCodeRedirect'],
        ]

    def _apply_wso2_weights(self):
        b = self._bump_weight
        # Coverage anchors
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['PasswordGrant', 'UserInfo'], 2.0)
        b(['ClientCredentials'], 1.8)
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.2)
        # Replay
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'], 2.8)
        b(['PasswordGrant', 'RefreshToken', 'RefreshToken'], 2.5)
        # Attack classes
        b(['AuthorizeBadRedirectUri'], 2.5)
        b(['AuthorizeOpenRedirect', 'Login'], 2.5)
        b(['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'], 2.3)
        b(['PasswordGrant', 'UseRefreshAsAccess'], 2.3)
        # WSO2-specific attacks
        b(['Authorize', 'Login', 'Wso2SessionKeyReplay'], 3.0)
        b(['Authorize', 'Wso2ConsentBypass', 'TokenExchange'], 3.0)
        b(['Wso2DCRRegister'], 2.5)
        b(['Wso2SCIM2Users'], 2.5)
        b(['Wso2AdminAPI'], 2.0)
        # PAR / Device / Implicit
        b(['PushedAuthorizationRequest', 'AuthorizePAR', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 1.8)
        b(['DeviceAuthorization'], 1.6)
        b(['AuthorizeImplicit'], 1.8)
        # WSO2 introspection (Basic auth required)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'], 2.3)
        # NEW: prioritize the deeper-state exploration seeds — these are
        # the ONLY sequences in the corpus that exercise prompt=none,
        # request_uri, tenant resolver, SQLi, and code-replay branches.
        b(['Wso2PromptNone'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Wso2PromptNone'], 3.0)
        b(['Wso2RequestUriSSRF'], 3.2)                                     # SSRF is high-value
        b(['Wso2RequestUriSSRF', 'Login', 'AuthCodeRedirect'], 2.5)
        b(['Wso2ScopeInjection', 'Login', 'AuthCodeRedirect'], 2.6)
        b(['Wso2ScopeInjection', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
           'Wso2AuthCodeReplay'], 3.5)                                     # code-reuse is critical
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
           'Wso2AuthCodeReplay', 'Wso2AuthCodeReplay'], 3.2)
        b(['Wso2TenantConfusion'], 2.4)
        b(['Wso2DCRSqlInjection'], 3.0)
        b(['Wso2DCRSqlInjection', 'Wso2SCIM2Users'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'Authorize',
           'Login', 'AuthCodeRedirect'], 2.2)

    # ============================== CASDOOR =============================
    def _load_casdoor_seeds(self):
        """Casdoor: OIDC core + Casdoor-specific CVE attack sequences.

        Casdoor supports: authorization_code+PKCE, password, client_credentials,
        refresh, introspect. No PAR/Device/Implicit/Revoke.
        """
        oidc_core = [
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['PasswordGrant', 'UserInfo'],
            ['ClientCredentials'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'],
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'],
        ]
        casdoor_specific = [
            # C2 (LOW): PKCE not enforced
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # C1 (MEDIUM): Introspection client_id substitution
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'],
            ['PasswordGrant', 'Introspect'],
            # C13 (LOW): Auth code replay race
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'],
            # C4 (LOW): Refresh token TOCTOU
            ['PasswordGrant', 'RefreshToken', 'RefreshToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'RefreshToken'],
            # C9 (MEDIUM): AutoSigninFilter — passwords in GET URL
            ['CasdoorAutoSigninPasswordInURL'],
            ['CasdoorAutoSigninPasswordInURL', 'UserInfo'],
            # C8 (MEDIUM): Session cookie flags
            ['Authorize', 'CasdoorSessionCookieFlags'],
            # C17 (INFO): CORS origin echo
            ['CasdoorTokenCorsOriginEcho'],
            ['CasdoorUserinfoCorsOpen'],
            # Auth code anti-replay
            ['Authorize', 'Login', 'AuthCodeRedirect', 'CasdoorAuthCodeReplay'],
            ['CasdoorAuthCodeReplay', 'TokenExchange'],
            # Scope escalation
            ['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Redirect URI
            ['AuthorizeBadRedirectUri'],
            ['AuthorizeOpenRedirect', 'Login'],
            # Client auth attacks
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenWrongClientSecret'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenBadCode'],
            # Cross-client
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
            # Token confusion
            ['PasswordGrant', 'UseRefreshAsAccess'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'],
            # Login replay / session
            ['Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['Authorize', 'Login', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Content-type manipulation
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeXML'],
            # Parameter flooding
            ['AuthorizeParamFlood100', 'Login'],
            # Guest/unauthorized probes
            ['UserInfo'],
            ['Introspect'],
            # Deep state chains
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE',
             'UserInfo', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'RefreshToken', 'Introspect', 'RefreshToken'],
        ]
        self.corpus = oidc_core + casdoor_specific

    def _apply_casdoor_weights(self):
        b = self._bump_weight
        # Coverage anchors
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['PasswordGrant', 'UserInfo'], 2.0)
        b(['ClientCredentials'], 1.8)
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.2)
        # C2 PKCE not enforced — signature attack
        b(['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'], 3.0)
        b(['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        # C1 Introspection client_id substitution — MEDIUM
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'], 2.8)
        b(['PasswordGrant', 'Introspect'], 2.5)
        # C9 AutoSigninFilter password in GET — MEDIUM
        b(['CasdoorAutoSigninPasswordInURL'], 3.0)
        b(['CasdoorAutoSigninPasswordInURL', 'UserInfo'], 3.2)
        # C8 Session cookie flags — MEDIUM
        b(['Authorize', 'CasdoorSessionCookieFlags'], 2.5)
        # C17 CORS origin echo
        b(['CasdoorTokenCorsOriginEcho'], 2.2)
        b(['CasdoorUserinfoCorsOpen'], 2.2)
        # Replay / TOCTOU
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'], 3.0)
        b(['PasswordGrant', 'RefreshToken', 'RefreshToken'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
           'RefreshToken', 'RefreshToken'], 2.5)
        # Attack classes
        b(['AuthorizeBadRedirectUri'], 2.5)
        b(['AuthorizeOpenRedirect', 'Login'], 2.5)
        b(['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenWrongClientSecret'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'], 2.5)
        b(['PasswordGrant', 'UseRefreshAsAccess'], 2.3)

    # ============================== ORY HYDRA ===========================
    def _load_ory_hydra_seeds(self):
        """Ory Hydra: OIDC core + Admin API attack sequences.

        Ory Hydra is a pure OAuth2 provider — no password grant, no user management.
        Uses admin API for login/consent acceptance (high-value attack surface).
        """
        oidc_core = [
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['ClientCredentials'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'],
        ]
        hydra_specific = [
            # Admin API probes (high-value attack surface)
            ['HydraAdminAPIProbe'],
            ['HydraClientCreation'],
            # PKCE attacks
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Replay
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'],
            ['ClientCredentials', 'RefreshToken', 'RefreshToken'],
            # Redirect URI
            ['AuthorizeBadRedirectUri'],
            ['AuthorizeOpenRedirect', 'Login'],
            ['AuthorizeRedirectSSRF'],
            # Introspect / Revoke
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'IntrospectEmptyToken', 'IntrospectMalformed'],
            # Scope escalation
            ['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Cross-client
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
            # Token confusion
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'],
            # PAR
            ['PushedAuthorizationRequest', 'AuthorizePAR', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['HydraParFlood'],
            # Implicit / Hybrid
            ['AuthorizeImplicit'],
            ['AuthorizeHybrid', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Consent bypass
            ['Authorize', 'Login', 'AuthCodeRedirect', 'Consent', 'TokenExchange'],
            # Content-type
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeXML'],
            # Admin API deep chains
            ['HydraAdminAPIProbe', 'HydraClientCreation', 'Authorize', 'Login',
             'AuthCodeRedirect', 'TokenExchange'],
            ['ClientCredentials', 'HydraAdminAPIProbe', 'Introspect'],
            ['HydraClientCreation', 'ClientCredentials', 'Introspect', 'RevokeToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'RefreshToken', 'RevokeToken', 'RefreshToken'],
        ]
        self.corpus = oidc_core + hydra_specific

    def _apply_ory_hydra_weights(self):
        b = self._bump_weight
        # Admin API is the most valuable attack surface — highest weights
        b(['HydraAdminAPIProbe'], 3.5)
        b(['HydraClientCreation'], 3.0)
        b(['HydraAdminAPIProbe', 'HydraClientCreation', 'Authorize', 'Login',
           'AuthCodeRedirect', 'TokenExchange'], 3.2)
        b(['ClientCredentials', 'HydraAdminAPIProbe', 'Introspect'], 3.0)
        # Coverage anchors
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        b(['ClientCredentials'], 2.0)
        # PKCE enforcement
        b(['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'], 3.0)
        b(['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        # Replay
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'], 3.0)
        b(['ClientCredentials', 'RefreshToken', 'RefreshToken'], 2.5)
        # Attack classes
        b(['AuthorizeBadRedirectUri'], 2.8)
        b(['AuthorizeOpenRedirect', 'Login'], 2.8)
        b(['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'], 2.5)
        b(['AuthorizeImplicit'], 2.0)
        b(['HydraParFlood'], 2.2)
        # Revoke / Introspect chains
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
           'RevokeToken', 'Introspect'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
           'RefreshToken', 'RevokeToken', 'RefreshToken'], 2.8)

    # ============================== ZITADEL =============================
    def _load_zitadel_seeds(self):
        """Zitadel: Full IAM / OIDC + MFA + multi-tenant + TokenExchange.

        Zitadel supports all standard OAuth2/OIDC flows plus:
          - gRPC + REST dual API surface
          - Multi-tenant organization isolation
          - MFA (TOTP, U2F, OTP)
          - Token Exchange (RFC 8693)
        """
        oidc_core = [
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['PasswordGrant', 'UserInfo'],
            ['ClientCredentials'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'],
            ['DeviceAuthorization'],
            ['Logout'],
        ]
        zitadel_specific = [
            # PKCE attacks
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Replay
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'],
            ['PasswordGrant', 'RefreshToken', 'RefreshToken'],
            # Redirect URI
            ['AuthorizeBadRedirectUri'],
            ['AuthorizeOpenRedirect', 'Login'],
            ['AuthorizeRedirectSSRF'],
            # Introspect / Revoke
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'],
            ['PasswordGrant', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'],
            # Scope escalation
            ['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Cross-client
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
            # Token confusion
            ['PasswordGrant', 'UseRefreshAsAccess'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'],
            # Token Exchange (RFC 8693)
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'ZitadelTokenExchangeImpersonation'],
            # Implicit / Hybrid
            ['AuthorizeImplicit'],
            ['AuthorizeHybrid', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # PAR
            ['PushedAuthorizationRequest', 'AuthorizePAR', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Zitadel-specific API probes
            ['ZitadelAPIProbe'],
            ['PasswordGrant', 'ZitadelAPIProbe'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'ZitadelAPIProbe'],
            # Multi-tenant isolation
            ['ZitadelOrgContextConfusion'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'ZitadelOrgContextConfusion'],
            # MFA bypass (C15/C16 vulnerability class)
            ['ZitadelMFABypass'],
            # Content-type
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeXML'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeNullContentType'],
            # Parameter flooding
            ['AuthorizeParamFlood100', 'Login'],
            # Session / state manipulation
            ['Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['Authorize', 'AuthCodeRedirect', 'TokenExchange'],
            # Deep chains
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'ZitadelAPIProbe', 'ZitadelOrgContextConfusion'],
            ['PushedAuthorizationRequest', 'AuthorizePAR', 'Login',
             'AuthCodeRedirect', 'TokenExchange', 'UserInfo', 'Introspect'],
            ['PasswordGrant', 'Introspect', 'RefreshToken', 'ZitadelMFABypass'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'RefreshToken', 'RevokeToken', 'ZitadelTokenExchangeImpersonation'],
        ]
        self.corpus = oidc_core + zitadel_specific

    def _apply_zitadel_weights(self):
        b = self._bump_weight
        # Multi-tenant / API access — highest value attacks
        b(['ZitadelOrgContextConfusion'], 3.5)
        b(['ZitadelAPIProbe'], 3.0)
        b(['ZitadelMFABypass'], 3.2)
        b(['ZitadelTokenExchangeImpersonation'], 3.0)
        b(['PasswordGrant', 'ZitadelAPIProbe'], 3.0)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
           'ZitadelOrgContextConfusion'], 3.2)
        # Coverage anchors
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        b(['PasswordGrant', 'UserInfo'], 2.0)
        b(['ClientCredentials'], 1.8)
        # PKCE enforcement
        b(['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'], 3.0)
        b(['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        # Replay
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'], 3.0)
        b(['PasswordGrant', 'RefreshToken', 'RefreshToken'], 2.8)
        # Attack classes
        b(['AuthorizeBadRedirectUri'], 2.8)
        b(['AuthorizeOpenRedirect', 'Login'], 2.8)
        b(['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'], 2.5)
        b(['PasswordGrant', 'UseRefreshAsAccess'], 2.5)
        # Zitadel deep chains
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
           'ZitadelAPIProbe', 'ZitadelOrgContextConfusion'], 3.2)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
           'RefreshToken', 'RevokeToken', 'ZitadelTokenExchangeImpersonation'], 3.0)
        b(['PasswordGrant', 'Introspect', 'RefreshToken', 'ZitadelMFABypass'], 2.8)
        # PAR / Device / Implicit
        b(['PushedAuthorizationRequest', 'AuthorizePAR', 'Login',
           'AuthCodeRedirect', 'TokenExchange'], 1.8)
        b(['DeviceAuthorization'], 1.6)
        b(['AuthorizeImplicit'], 1.8)

    # ------------------------------------------------------------------
    # Authentik seeds + weights
    # ------------------------------------------------------------------
    def _load_authentik_seeds(self):
        oidc_core = [
            # Standard auth code + PKCE
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Client credentials
            ['ClientCredentials'],
            # Refresh + revoke + introspect
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'RefreshToken', 'UserInfo'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'RevokeToken', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'Introspect'],
            # Bad inputs
            ['AuthorizeBadRedirectUri'],
            ['TokenBadCode'],
            ['TokenWrongClientSecret'],
            ['UserInfoWrongToken'],
        ]
        authentik_specific = [
            # Device flow
            ['DeviceAuthorization'],
            # Token confusion
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'UseRefreshAsAccess'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'UseIDTokenAsAccess'],
            # End session
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Logout'],
            # Scope attacks
            ['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect',
             'TokenExchange'],
            ['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # Authentik-specific
            ['AuthentikFlowStageBypass'],
            ['AuthentikCSRFTokenReuse'],
            ['AuthentikDeviceCodeFuzz'],
            ['AuthentikIntrospectCrossClient'],
            ['AuthentikTokenConfusion'],
            ['AuthentikScopeEscalation'],
            ['AuthentikEndSessionRedirect'],
            # PKCE enforcement
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect',
             'TokenExchange'],
            # Implicit / hybrid
            ['AuthorizeImplicit'],
            ['AuthorizeHybrid'],
            # Open redirect
            ['AuthorizeOpenRedirect', 'Login'],
            # Cross-client
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
        ]
        self.corpus = oidc_core + authentik_specific

    def _apply_authentik_weights(self):
        b = self._bump_weight
        # Authentik-specific attacks — highest value
        b(['AuthentikFlowStageBypass'], 3.5)
        b(['AuthentikCSRFTokenReuse'], 3.2)
        b(['AuthentikIntrospectCrossClient'], 3.0)
        b(['AuthentikTokenConfusion'], 3.0)
        b(['AuthentikScopeEscalation'], 3.0)
        b(['AuthentikEndSessionRedirect'], 2.8)
        # Coverage anchors
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        # PKCE enforcement
        b(['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'], 3.0)
        b(['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        # Token confusion
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseRefreshAsAccess'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'], 2.8)
        # Replay + redirect
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'], 3.0)
        b(['AuthorizeBadRedirectUri'], 2.8)
        b(['AuthorizeOpenRedirect', 'Login'], 2.8)
        # Scope attacks
        b(['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)
        b(['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.8)

    def _load_simplelogin_seeds(self):
        oauth_core = [
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'UserInfo'],
            ['AuthorizeBadRedirectUri'],
            ['TokenBadCode'],
            ['TokenWrongClientSecret'],
            ['UserInfoWrongToken'],
        ]
        simplelogin_specific = [
            ['SimpleLoginCSRFByass'],
            ['SimpleLoginOpenRedirect'],
            ['SimpleLoginTokenReplay'],
            ['SimpleLoginScopeManipulation'],
            ['SimpleLoginClientImpersonation'],
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
            ['AuthorizeOpenRedirect', 'Login'],
        ]
        self.corpus = oauth_core + simplelogin_specific

    def _apply_simplelogin_weights(self):
        b = self._bump_weight
        b(['SimpleLoginCSRFByass'], 3.5)
        b(['SimpleLoginOpenRedirect'], 3.2)
        b(['SimpleLoginClientImpersonation'], 3.0)
        b(['SimpleLoginTokenReplay'], 2.8)
        b(['SimpleLoginScopeManipulation'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        b(['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'], 3.0)
        b(['AuthorizeBadRedirectUri'], 2.8)
        b(['AuthorizeOpenRedirect', 'Login'], 2.8)

    def _load_nodeoidc_seeds(self):
        """Seed corpus for node-oidc-provider (full OIDC)."""
        oauth_core = [
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo', 'Introspect'],
            ['ClientCredentials'],
            ['AuthorizeBadRedirectUri'],
            ['TokenBadCode'],
            ['TokenWrongClientSecret'],
            ['UserInfoWrongToken'],
            ['DeviceAuthorization'],
        ]
        nodeoidc_specific = [
            ['NodeOIDCPKCEPlain'],
            ['NodeOIDCCodeReplay'],
            ['NodeOIDCInvalidVerifier'],
            ['NodeOIDCIntrospectCrossClient'],
            ['NodeOIDCScopeEscalation'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'NodeOIDCCodeReplay'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'NodeOIDCIntrospectCrossClient'],
        ]
        self.corpus = oauth_core + nodeoidc_specific

    def _apply_nodeoidc_weights(self):
        b = self._bump_weight
        b(['NodeOIDCPKCEPlain'], 3.5)
        b(['NodeOIDCCodeReplay'], 3.5)
        b(['NodeOIDCInvalidVerifier'], 3.2)
        b(['NodeOIDCIntrospectCrossClient'], 3.0)
        b(['NodeOIDCScopeEscalation'], 3.0)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken'], 2.5)
        b(['AuthorizeBadRedirectUri'], 2.8)

    def _load_logto_seeds(self):
        """Seed corpus for Logto (TypeScript/Node.js OIDC provider)."""
        oauth_core = [
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo', 'Introspect'],
            ['ClientCredentials'],
            ['AuthorizeBadRedirectUri'],
            ['TokenBadCode'],
            ['TokenWrongClientSecret'],
            ['UserInfoWrongToken'],
            ['DeviceAuthorization'],
            ['PushedAuthorizationRequest', 'AuthorizePAR', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
        ]
        logto_specific = [
            ['LogtoPKCEPlain'],
            ['LogtoCodeReplay'],
            ['LogtoIntrospectCrossClient'],
            ['LogtoScopeEscalation'],
            ['LogtoContentTypeJSON'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'LogtoCodeReplay'],
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange',
             'LogtoIntrospectCrossClient'],
        ]
        self.corpus = oauth_core + logto_specific

    def _apply_logto_weights(self):
        b = self._bump_weight
        b(['LogtoPKCEPlain'], 3.5)
        b(['LogtoCodeReplay'], 3.5)
        b(['LogtoIntrospectCrossClient'], 3.0)
        b(['LogtoScopeEscalation'], 3.0)
        b(['LogtoContentTypeJSON'], 3.2)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'Introspect'], 2.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken'], 2.8)
        b(['AuthorizeBadRedirectUri'], 2.8)
        b(['PushedAuthorizationRequest', 'AuthorizePAR', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.0)

    # ============================== SHIRO ==============================
    def _load_shiro_seeds(self):
        """Apache Shiro 2.2.0 OAuth2 Server. PKCE required, no PAR/Device/Implicit.

        Shiro supports: auth_code (PKCE required), password, client_credentials,
        refresh, introspect, revoke, userinfo.
        """
        self.corpus = [
            # ── Core success flows ──
            ['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['PasswordGrant', 'UserInfo'],
            ['ClientCredentials'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'],
            # ── PKCE enforcement (Shiro requires PKCE — these should be rejected) ──
            ['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'],
            ['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # ── Auth-code replay ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'],
            ['PasswordGrant', 'RefreshToken', 'RefreshToken'],
            ['Login', 'AuthCodeRedirect', 'TokenExchange'],
            # ── Redirect URI validation ──
            ['AuthorizeBadRedirectUri'],
            ['AuthorizeOpenRedirect', 'Login'],
            ['AuthorizeRedirectSSRF'],
            # ── Token confusion ──
            ['PasswordGrant', 'UseRefreshAsAccess'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'],
            # ── Scope escalation ──
            ['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'],
            ['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'],
            # ── Client auth attacks ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenWrongClientSecret'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenBadCode'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'],
            ['TokenExchangeInvalidClient', 'TokenExchangeValidClientWrongSecret'],
            # ── Introspect / Revoke ──
            ['PasswordGrant', 'RevokeToken', 'Introspect'],
            ['PasswordGrant', 'RevokeToken', 'RefreshToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'],
            ['PasswordGrant', 'Introspect'],
            # ── Content-type manipulation ──
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeXML'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeNullContentType'],
            # ── Parameter flooding ──
            ['AuthorizeParamFlood100', 'Login'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeParamFlood'],
            # ── Deep chains ──
            ['PasswordGrant', 'RevokeToken', 'Introspect', 'RefreshToken'],
            ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken'],
        ]

    def _apply_shiro_weights(self):
        b = self._bump_weight
        # PKCE enforcement is the signature attack class for Shiro (PKCE required)
        b(['AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchangeNoPKCE'], 3.5)
        b(['AuthorizePKCEMethodConfusion', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 3.0)
        # Core coverage anchors
        b(['AuthorizePKCES256', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.2)
        b(['PasswordGrant', 'UserInfo'], 2.0)
        b(['ClientCredentials'], 1.8)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RefreshToken', 'UserInfo'], 2.0)
        # Auth-code replay
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'TokenExchange'], 3.0)
        b(['PasswordGrant', 'RefreshToken', 'RefreshToken'], 2.8)
        b(['Login', 'AuthCodeRedirect', 'TokenExchange'], 2.3)
        # Redirect URI bypass
        b(['AuthorizeBadRedirectUri'], 2.8)
        b(['AuthorizeOpenRedirect', 'Login'], 2.5)
        b(['AuthorizeRedirectSSRF'], 2.5)
        # Token confusion
        b(['PasswordGrant', 'UseRefreshAsAccess'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UseIDTokenAsAccess'], 2.3)
        # Scope escalation
        b(['AuthorizeScopeEscalation', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo'], 2.8)
        b(['AuthorizeScopeAdmin', 'Login', 'AuthCodeRedirect', 'TokenExchange'], 2.5)
        # Client auth bypass
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenWrongClientSecret'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchangeWrongClient'], 2.5)
        # Introspect / Revoke chains
        b(['PasswordGrant', 'RevokeToken', 'Introspect'], 2.5)
        b(['PasswordGrant', 'RevokeToken', 'RefreshToken'], 2.5)
        b(['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'RevokeToken', 'Introspect'], 2.3)

    # ==================================================================
    # END seed loaders + weight appliers
    # ==================================================================

    def _choose_base_sequence(self) -> int:
        """AFLnet-style seed selection with favored/regular split.

        - 85% of the time: pick from sequences marked favored (new coverage
          or oracle-triggering). Within favored, use weight-proportional.
        - 15% of the time: pick from the full corpus with weight-proportional
          probability. This keeps under-explored regular seeds alive.
        - If no favored seeds exist yet (warm-up), fall through to full corpus.
        """
        if self._disable_feedback:
            # DG-off arm: deterministic round-robin over a frozen corpus.
            if not self.corpus:
                return 0
            idx = self._rr_counter % len(self.corpus)
            self._rr_counter += 1
            return idx

        if not self.selection_weights:
            return 0

        # Keep favored_flags in sync with selection_weights length defensively
        if len(self.favored_flags) < len(self.selection_weights):
            self.favored_flags.extend([False] * (len(self.selection_weights) - len(self.favored_flags)))
        elif len(self.favored_flags) > len(self.selection_weights):
            self.favored_flags = self.favored_flags[:len(self.selection_weights)]

        use_favored = random.random() < 0.85 and any(self.favored_flags)
        if use_favored:
            indices = [i for i, f in enumerate(self.favored_flags) if f]
            weights = [self.selection_weights[i] for i in indices]
        else:
            indices = list(range(len(self.selection_weights)))
            weights = list(self.selection_weights)

        total = sum(weights) or 1.0
        r = random.random() * total
        acc = 0.0
        for local_idx, w in enumerate(weights):
            acc += w
            if r <= acc:
                return indices[local_idx]
        return indices[-1]

    def _update_selection_weights(self, is_new_state: bool,
                                  selected_idx: int = -1,
                                  gave_coverage: bool = False,
                                  oracle_hit: bool = False):
        """Targeted weight update — replaces the prior uniform cap-and-collapse.

        Before: every weight was multiplied by (1.05 if is_new_state else 1.0)
        and then capped at 5.0 — this erased any differentiation earned by
        high-value sequences within one iteration.

        After: only the SELECTED sequence is rewarded, and only when it
        actually contributed new coverage or triggered an oracle. Non-selected
        sequences are left alone. Favored sequences retain their full weight
        (capped at a much higher ceiling of 50.0).
        """
        if self._disable_feedback:
            # DG-off arm: weights frozen.
            return

        if selected_idx < 0 or selected_idx >= len(self.selection_weights):
            # Backwards-compatible legacy path: no specific index given.
            # Apply a MUCH gentler decay rather than a hard cap, so high-value
            # sequences retain their relative priority.
            if is_new_state:
                self.selection_weights = [
                    min(w * 1.02, 50.0) for w in self.selection_weights
                ]
            return

        # Selected-sequence reward (multiplicative, compounded per hit)
        multiplier = 1.0
        if gave_coverage:
            multiplier *= 1.30  # +30% for each new-coverage hit
        if oracle_hit:
            multiplier *= 1.50  # +50% for each oracle-triggering run
        if is_new_state:
            multiplier *= 1.10

        if multiplier > 1.0:
            old = self.selection_weights[selected_idx]
            new = min(old * multiplier, 50.0)
            self.selection_weights[selected_idx] = new

        # Mild saturation-era damping: if the WHOLE corpus has gone a long
        # time without probe novelty, slowly pull high weights back toward
        # the median to re-explore regular seeds. This replaces the blunt
        # dump-interval escalation.
        if self._stagnant_probe_rounds > 0 and self._stagnant_probe_rounds % 40 == 0:
            median = sorted(self.selection_weights)[len(self.selection_weights) // 2]
            self.selection_weights = [
                w * 0.95 + median * 0.05 for w in self.selection_weights
            ]

    def _mutate_sequence(self, seq: List[str]) -> List[str]:
        mutated = list(seq)
        # Standard mutation rates.
        shuffle_rate = 0.25
        insert_rate = 0.20

        # Profile-aware "optional symbol" pool: drop symbols the target
        # cannot service, so we don't insert guaranteed-404 steps.
        unsupported = self._get_unsupported_symbols()

        if random.random() < shuffle_rate and len(mutated) > 1:
            random.shuffle(mutated)
        if random.random() < insert_rate and len(mutated) > 0:
            optional_symbols = [
                'Consent', 'Introspect',
                'AuthorizeNoPKCE', 'AuthorizeBadRedirectUri',
                'TokenBadCode', 'TokenWrongClientSecret',
                'UserInfoWrongToken'
            ]
            # Target-specific insertion pool — adds breadth to the
            # per-iteration symbol reach without breaking other targets.
            # (CVE-knowledge ablation: these attack symbols are profiling
            # output distilled from historical CVE/audit analysis.)
            if not self._disable_cve_patterns:
                if self.target_type == 'wso2':
                    optional_symbols += [
                        'Wso2PromptNone', 'Wso2RequestUriSSRF',
                        'Wso2ScopeInjection', 'Wso2AuthCodeReplay',
                        'Wso2TenantConfusion', 'Wso2DCRSqlInjection',
                        'Wso2SessionKeyReplay',
                    ]
                elif self.target_type == 'casdoor':
                    optional_symbols += [
                        'CasdoorAutoSigninPasswordInURL', 'CasdoorSessionCookieFlags',
                        'CasdoorTokenCorsOriginEcho', 'CasdoorUserinfoCorsOpen',
                        'CasdoorAuthCodeReplay',
                    ]
                elif self.target_type == 'ory_hydra':
                    optional_symbols += [
                        'HydraAdminAPIProbe', 'HydraClientCreation',
                        'HydraParFlood',
                    ]
                elif self.target_type == 'zitadel':
                    optional_symbols += [
                        'ZitadelAPIProbe', 'ZitadelOrgContextConfusion',
                        'ZitadelMFABypass', 'ZitadelTokenExchangeImpersonation',
                    ]
                elif self.target_type == 'shiro':
                    optional_symbols += [
                        'AuthorizeNoPKCE', 'AuthorizePKCEMethodConfusion',
                        'PasswordGrant', 'RevokeToken', 'Introspect',
                        'UseRefreshAsAccess', 'AuthorizeScopeAdmin',
                        'TokenBadCode', 'TokenWrongClientSecret',
                    ]
                elif self.target_type == 'authentik':
                    optional_symbols += [
                        'AuthentikFlowStageBypass', 'AuthentikCSRFTokenReuse',
                        'AuthentikDeviceCodeFuzz', 'AuthentikIntrospectCrossClient',
                        'AuthentikTokenConfusion', 'AuthentikScopeEscalation',
                        'AuthentikEndSessionRedirect',
                    ]
                elif self.target_type == 'simplelogin':
                    optional_symbols += [
                        'SimpleLoginCSRFByass', 'SimpleLoginOpenRedirect',
                        'SimpleLoginTokenReplay', 'SimpleLoginScopeManipulation',
                        'SimpleLoginClientImpersonation',
                    ]
                elif self.target_type == 'nodeoidc':
                    optional_symbols += [
                        'NodeOIDCPKCEPlain', 'NodeOIDCCodeReplay',
                        'NodeOIDCInvalidVerifier', 'NodeOIDCIntrospectCrossClient',
                        'NodeOIDCScopeEscalation',
                    ]
                elif self.target_type == 'cxf_oauth':
                    optional_symbols.extend([
                        'RefreshToken',     # C45: expired refresh token reuse
                        'Introspect',       # C47/C49: cache DoS + JSON injection
                    ])
                elif self.target_type == 'logto':
                    optional_symbols += [
                        'LogtoPKCEPlain', 'LogtoCodeReplay',
                        'LogtoIntrospectCrossClient', 'LogtoScopeEscalation',
                        'LogtoContentTypeJSON',
                    ]
            optional_symbols = [s for s in optional_symbols if s not in unsupported]
            if optional_symbols:
                mutated.insert(random.randint(0, len(mutated)), random.choice(optional_symbols))
        if random.random() < 0.15 and len(mutated) > 1:
            del mutated[random.randrange(len(mutated))]
        if random.random() < 0.2 and len(mutated) > 0:
            replace_map = {
                'Authorize': ['AuthorizeNoPKCE', 'AuthorizeBadRedirectUri'],
                'TokenExchange': ['TokenBadCode', 'TokenWrongClientSecret',
                                  'TokenExchangeWrongClient',
                                  'TokenExchangeParamFlood'],
                'UserInfo': ['UserInfoWrongToken'],
                'Login': ['Login'],
                'Introspect': ['IntrospectEmptyToken', 'IntrospectMalformed'],
                'RefreshToken': ['RefreshToken'],
            }
            # WSO2: widen the Authorize replacement pool so every
            # iteration has a realistic chance of reaching a deeper
            # OAuth endpoint branch (prompt=none, request_uri, scope).
            # (CVE-knowledge ablation: target-specific extensions gated.)
            if not self._disable_cve_patterns:
                if self.target_type == 'wso2':
                    replace_map['Authorize'] = replace_map['Authorize'] + [
                        'Wso2PromptNone', 'Wso2RequestUriSSRF',
                        'Wso2ScopeInjection', 'Wso2TenantConfusion',
                    ]
                    replace_map['TokenExchange'] = replace_map['TokenExchange'] + [
                        'Wso2AuthCodeReplay',
                    ]
                elif self.target_type == 'shiro':
                    replace_map['Authorize'] = replace_map['Authorize'] + [
                        'AuthorizePKCES256', 'AuthorizePKCEMethodConfusion',
                    ]
                    replace_map['TokenExchange'] = replace_map['TokenExchange'] + [
                        'TokenExchangeXML', 'TokenExchangeParamFlood',
                    ]
                elif self.target_type == 'authentik':
                    replace_map['UserInfo'] = replace_map['UserInfo'] + [
                        'AuthentikTokenConfusion', 'AuthentikScopeEscalation',
                    ]
                    replace_map['Authorize'] = replace_map['Authorize'] + [
                        'AuthentikFlowStageBypass',
                    ]
                elif self.target_type == 'simplelogin':
                    replace_map['Authorize'] = replace_map['Authorize'] + [
                        'SimpleLoginOpenRedirect', 'SimpleLoginCSRFByass',
                    ]
                    replace_map['TokenExchange'] = replace_map['TokenExchange'] + [
                        'SimpleLoginTokenReplay',
                    ]
                elif self.target_type == 'nodeoidc':
                    replace_map['Authorize'] = replace_map['Authorize'] + [
                        'NodeOIDCPKCEPlain',
                    ]
                    replace_map['TokenExchange'] = replace_map['TokenExchange'] + [
                        'NodeOIDCCodeReplay', 'NodeOIDCInvalidVerifier',
                    ]
                elif self.target_type == 'logto':
                    replace_map['Authorize'] = replace_map['Authorize'] + [
                        'LogtoPKCEPlain',
                    ]
                    replace_map['TokenExchange'] = replace_map['TokenExchange'] + [
                        'LogtoCodeReplay', 'LogtoContentTypeJSON',
                    ]
            i = random.randrange(len(mutated))
            candidates = replace_map.get(mutated[i], [])
            cand = [c for c in candidates if c not in unsupported]
            has_standard_flow = all(s in mutated for s in
                ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange'])
            if cand and not (has_standard_flow and mutated[i] == 'TokenExchange'):
                mutated[i] = random.choice(cand)
        if random.random() < 0.1 and len(mutated) > 0:
            i = random.randrange(len(mutated))
            mutated.insert(i, mutated[i])

        # Canonicalize flow order (configurable)
        if (self.config.get('fuzzing', {}).get('canonicalize_sequences', True)):
            order = ['Authorize', 'AuthorizeNoPKCE', 'Login', 'AuthCodeRedirect', 'TokenExchange', 'UserInfo']
            present = []
            seen = set()
            for s in order:
                if s in mutated and s not in seen:
                    present.append(s); seen.add(s)
            others = [s for s in mutated if s not in seen]
            mutated = present + others

        # Insert missing prerequisite steps
        syms = set(mutated)
        if 'Login' in syms and ('Authorize' not in syms and 'AuthorizeNoPKCE' not in syms):
            prefix = 'AuthorizeNoPKCE' if 'AuthorizeNoPKCE' not in unsupported else 'Authorize'
            mutated.insert(0, prefix)
        if 'TokenExchange' in syms and 'AuthCodeRedirect' not in syms:
            idx = mutated.index('TokenExchange')
            mutated.insert(max(0, idx), 'AuthCodeRedirect')
        if ('UserInfo' in syms
                and 'UserInfo' not in unsupported
                and ('TokenExchange' not in syms and 'PasswordGrant' not in syms)):
            idx = mutated.index('UserInfo')
            mutated.insert(max(0, idx), 'PasswordGrant')
        # Introspect and RevokeToken require a token — ensure a token-producing
        # step precedes them, otherwise CXF throws NPE (ServerError).
        token_producing = {'TokenExchange', 'PasswordGrant', 'ClientCredentials'}
        for dep_sym in ('Introspect', 'IntrospectEmptyToken', 'IntrospectMalformed',
                        'RevokeToken', 'RefreshToken'):
            if dep_sym in syms and not (syms & token_producing):
                idx = mutated.index(dep_sym)
                mutated.insert(max(0, idx), 'PasswordGrant')
                syms.add('PasswordGrant')
                break

        # Enforce Authorize → Login → AuthCodeRedirect order when all three present
        if 'Authorize' in mutated and 'Login' in mutated and 'AuthCodeRedirect' in mutated:
            auth_idx = mutated.index('Authorize')
            login_idx = mutated.index('Login')
            redirect_idx = mutated.index('AuthCodeRedirect')

            if not (auth_idx < login_idx < redirect_idx):
                elements = []
                indices = sorted([auth_idx, login_idx, redirect_idx], reverse=True)
                for idx in indices:
                    elements.append(mutated.pop(idx))
                elements.reverse()

                insert_pos = min(auth_idx, login_idx, redirect_idx)
                for element in ['Authorize', 'Login', 'AuthCodeRedirect']:
                    mutated.insert(insert_pos, element)
                    insert_pos += 1

        # Final: scrub any steps the active target cannot service.
        if unsupported:
            mutated = [s for s in mutated if s not in unsupported]

        if not mutated:
            # Fall back to a safe, profile-compatible base sequence.
            fallback = [s for s in seq if s not in unsupported]
            mutated = fallback if fallback else list(seq)

        return mutated

    def _dump_and_update_granular_coverage(self, force: bool = True) -> GranularCoverageData:
        """Dump并更新细粒度覆盖率数据（支持按需 dump）

        Differential-by-default: when self._use_differential_dump is True
        (default for JaCoCo targets) each call dumps+resets JaCoCo probes
        and parses the *per-iteration* coverage. Cumulative state is
        preserved side-channel via merge_exec_files so overall progress
        is still reported.

        TTL semantics: a non-force call within _coverage_cache_ttl seconds
        of the last successful dump returns the cached result without
        re-probing the JVM. A non-force call *beyond* the TTL is silently
        upgraded to a forced dump to prevent stale guidance.
        """
        # State-based targets (Go + Python) use GoCoverageManager directly
        if self.target_type in ('authelia', 'casdoor', 'ory_hydra', 'zitadel', 'authentik', 'simplelogin', 'nodeoidc', 'logto'):
            go_cov = getattr(self, 'go_coverage', None)
            if go_cov is None:
                mgr = getattr(self, 'authelia_manager', None) or getattr(self, 'target_manager', None)
                if mgr:
                    go_cov = getattr(mgr, 'go_coverage', None)

            coverage = GranularCoverageData()
            if go_cov:
                try:
                    go_data = go_cov.collect_coverage()
                    if go_data:
                        coverage.instructions_covered = go_data.instructions_covered
                        coverage.instructions_total = go_data.instructions_total
                        coverage.lines_covered = go_data.lines_covered
                        coverage.lines_total = go_data.lines_total
                        coverage.coverage_percentage = go_data.coverage_percentage
                        coverage.module_coverage = go_data.module_coverage or {}
                        coverage.branches_covered = go_data.branches_covered
                        coverage.branches_total = go_data.branches_total
                except Exception as e:
                    print(f"[GoCoverage] Collection error: {e}")

            self.current_coverage = coverage
            self._coverage_cache_ts = time.time()
            return coverage

        # Keycloak and all JVM OIDC targets with JaCoCo
        if not self.jacoco:
            return GranularCoverageData()

        # TTL-gated stale-cache guard: if caller says !force but our cache
        # is older than the TTL, upgrade to a forced dump. This eliminates
        # the silent-staleness problem where weights were computed against
        # 49-iteration-old coverage data.
        cache_age = time.time() - self._coverage_cache_ts
        if not force and cache_age < self._coverage_cache_ttl and self.current_coverage:
            return self.current_coverage
        if not force and cache_age >= self._coverage_cache_ttl:
            force = True  # stale: upgrade silently

        try:
            jp = self.config.get('jacoco', {}).get('agent_port', 6300)

            # === Differential-by-default path ===
            if self._use_differential_dump:
                coverage = self._dump_differential_coverage()
                # _dump_differential_coverage updates self.current_coverage
                # (cumulative snapshot) and returns the differential.
                self._coverage_cache_ts = time.time()
                return coverage

            # === Legacy non-reset path (kept for opt-out diagnostics) ===
            self.jacoco.dump_coverage(port=jp)
            xml = self.jacoco.generate_report()
            if xml:
                granular_coverage = self.jacoco.parse_granular_coverage_xml(xml)
                if granular_coverage.instructions_total == 0:
                    try:
                        mods = self.config.get('jacoco', {}).get('classpaths_modules', [])
                        if mods:
                            print("[Coverage] Totals=0/0, switching to module classpaths and regenerating report")
                            self.jacoco.set_classpaths(mods)
                            xml2 = self.jacoco.generate_report()
                            if xml2:
                                granular_coverage = self.jacoco.parse_granular_coverage_xml(xml2)
                    except Exception as e2:
                        print(f"[Coverage] Adaptive fallback failed: {e2}")
                self.current_coverage = granular_coverage
                self._coverage_cache_ts = time.time()
                # Same rationale as above: defer probe_set commit to the gain oracle.
                return granular_coverage
        except Exception as e:
            print(f"Error dumping and updating granular coverage: {e}")
        return GranularCoverageData()

    def _dump_differential_coverage(self) -> GranularCoverageData:
        if not self.jacoco:
            return GranularCoverageData()
        try:
            jp = self.config.get('jacoco', {}).get('agent_port', 6300)

            current_exec = os.path.join(self.jacoco.work_dir, "coverage.exec")

            # Disk guard
            try:
                import shutil as _sh
                free_mb = _sh.disk_usage(self.jacoco.work_dir).free // (1024 * 1024)
                if free_mb < 512:
                    print(f"[Coverage] Aborting dump: only {free_mb} MB free; "
                          f"keeping prior snapshot.")
                    return GranularCoverageData()
            except Exception:
                pass

            if not self.jacoco.dump_coverage_reset(port=jp):
                print("[Coverage] Dump failed — keeping prior snapshot")
                return GranularCoverageData()

            # Generate report from the single cumulative exec
            # (deltas are appended by the CLI; the union report keeps
            #  cumulative totals while each dump fetches only the delta
            #  since the previous --reset — bounds coverage.exec growth)
            self.jacoco.max_exec_mb = 400  # XML size is class-universe-bound
            xml = self.jacoco.generate_report()
            if not xml:
                return GranularCoverageData()

            coverage = self.jacoco.parse_granular_coverage_xml(xml)

            # Monotonic promotion: never regress
            if coverage.instructions_covered >= self.current_coverage.instructions_covered:
                self.current_coverage = coverage
                if coverage.instructions_covered > self.baseline_coverage.instructions_covered:
                    self.baseline_coverage = coverage
            else:
                print(f"[Coverage] Ignoring regressive read "
                      f"({coverage.instructions_covered} < "
                      f"{self.current_coverage.instructions_covered})")

            return coverage
        except Exception as e:
            print(f"[Coverage] Differential dump exception: {e}")
            return GranularCoverageData()

    def _coverage_gain(self) -> float:
        return (self.current_coverage.coverage_percentage - self.baseline_coverage.coverage_percentage)

    def _has_granular_coverage_gain(self, new_coverage: GranularCoverageData) -> bool:
        """True iff the iteration exercised code not seen before.

        Primary oracle: per-iteration probe fingerprint novelty against the
        cumulative _global_probe_set. This is the AFLnet "virgin bits"
        equivalent and is immune to cumulative percentage saturation.

        IMPORTANT: when running in differential-dump mode, `new_coverage`
        arrives as the per-iteration diff (what happened since last --reset),
        whose fingerprint is too coarse to ever grow (< 10% per module →
        always the `:0` bucket). The fingerprint MUST be computed from the
        cumulative snapshot self.current_coverage, which grows monotonically
        as new classes/methods get instrumented. Only the cumulative
        fingerprint can exhibit novel buckets, hot methods, or branch/instr
        transitions across iterations.
        """
        # Pick the snapshot that actually grows: cumulative if available,
        # otherwise fall back to whatever the caller passed in.
        probe_snapshot = self.current_coverage if (
            self.current_coverage and self.current_coverage.instructions_total > 0
        ) else new_coverage

        # === PRIMARY: virgin-bits probe novelty against cumulative set ===
        if probe_snapshot and (probe_snapshot.hot_methods or probe_snapshot.module_coverage
                               or probe_snapshot.instructions_covered):
            fp = probe_snapshot.probe_fingerprint()
            novel = fp - self._global_probe_set
            if novel:
                # Commit novelty into the cumulative set — this is the ONLY
                # place where _global_probe_set should be mutated during a
                # gain evaluation; any earlier commit breaks the oracle.
                self._global_probe_set.update(novel)
                self._stagnant_probe_rounds = 0
                return True

        # Everything below compares the cumulative snapshot (grows) against
        # baseline_coverage (also cumulative, refreshed every N iterations),
        # so the comparison is apples-to-apples.
        cmp_cov = probe_snapshot

        # === SECONDARY: cumulative percentage (works pre-saturation) ===
        if cmp_cov.coverage_percentage > self.baseline_coverage.coverage_percentage:
            return True

        # === SECONDARY: module-level delta ===
        for module, coverage in (cmp_cov.module_coverage or {}).items():
            if coverage > self.baseline_coverage.module_coverage.get(module, 0):
                return True

        # === SECONDARY: hot method novelty vs baseline ===
        new_hot = cmp_cov.hot_methods - self.baseline_coverage.hot_methods
        if new_hot:
            return True

        self._stagnant_probe_rounds += 1
        return False

    def _is_interesting(self,
                        has_coverage_gain: bool,
                        is_new_state: bool,
                        results: List[str],
                        symbols: List[str],
                        oracle_hits: List[Dict]) -> bool:
        last_status = results[-1] if results else ''
        last_symbol = symbols[-1] if symbols else ''

        # Rule 0 — reject sequences that are entirely transport-level noise.
        # Status0 (exception-path in OAuthSUT.execute_symbol), UnknownSymbol
        # (dispatch miss) and the WSO2 login_no_sdk short-circuit carry no
        # real protocol signal, so they must never be promoted into the
        # corpus regardless of what granular coverage reports.
        error_only_tokens = ('Status0', 'UnknownSymbol', 'Skipped',
                             'login_no_sdk', 'login_precondition_unmet',
                             'login_transport', 'login_timeout')
        if results and all(r in error_only_tokens for r in results):
            return False

        # Rule 2a — CRITICAL oracle hits always promote (crash-like).
        if any(o.get('severity') == 'CRITICAL' for o in oracle_hits):
            return True

        # Rule 2b — HIGH/MEDIUM oracle hits only promote when they ALSO bring
        # coverage gain OR when the oracle type is not in the known-FP list.
        # This prevents REFRESH_REPLAY-style runtime FP from saturating favored.
        high_med = [o for o in oracle_hits if o.get('severity') in ('HIGH', 'MEDIUM')]
        if high_med:
            fp_prone_types = {'REFRESH_REPLAY'}  # add more as you characterize them
            non_fp = [o for o in high_med if o.get('type') not in fp_prone_types]
            if non_fp and has_coverage_gain:
                return True
            if non_fp and any(o.get('severity') == 'HIGH' for o in non_fp):
                # HIGH non-FP still promotes even without coverage gain, but only once per template.
                return True
            # FP-prone HIGH with zero coverage gain: DO NOT promote.

        # Rule 1 — default: must have actual coverage gain.
        return bool(has_coverage_gain)

    def _maybe_refresh_baseline(self, current_coverage: GranularCoverageData):
        """Unconditionally rotate baseline every N iterations.

        This breaks the circular dependency "baseline updates only on
        detected gain". Once the cumulative-percentage oracle saturates,
        the old code could never refresh baseline, making recovery
        impossible. Here we roll it forward on a pure time-based trigger.

        Policy:
          - Always take the current cumulative snapshot (not the differential).
          - Preserve hot_methods union so we don't lose track of cumulative
            coverage signal inside the new baseline.
        """
        if self._disable_feedback:
            # DG-off arm: baseline rotation is feedback machinery.
            return
        self._iterations_since_baseline_refresh += 1
        if self._iterations_since_baseline_refresh < self._baseline_refresh_every:
            return

        self._iterations_since_baseline_refresh = 0
        # Use the cumulative snapshot (self.current_coverage) rather than the
        # differential passed in, so baseline tracks absolute progress.
        snap = self.current_coverage if self.current_coverage else current_coverage
        if snap and snap.instructions_total > 0:
            # Union hot_methods so we don't regress the baseline's method set
            merged_hot = set(self.baseline_coverage.hot_methods or set())
            merged_hot.update(snap.hot_methods or set())
            new_baseline = GranularCoverageData()
            new_baseline.instructions_covered = snap.instructions_covered
            new_baseline.instructions_total = snap.instructions_total
            new_baseline.lines_covered = snap.lines_covered
            new_baseline.lines_total = snap.lines_total
            new_baseline.branches_covered = snap.branches_covered
            new_baseline.branches_total = snap.branches_total
            new_baseline.methods_covered = snap.methods_covered
            new_baseline.methods_total = snap.methods_total
            new_baseline.coverage_percentage = snap.coverage_percentage
            new_baseline.module_coverage = dict(snap.module_coverage or {})
            new_baseline.hot_methods = merged_hot
            self.baseline_coverage = new_baseline
            print(f"[Coverage] Baseline refreshed (unconditional): "
                  f"%={new_baseline.coverage_percentage:.2f}%, "
                  f"hot_methods={len(merged_hot)}, "
                  f"global_probes={len(self._global_probe_set)}")
    
    def _calculate_sequence_weight(self, sequence: List[str], results: List[str], 
                                 coverage_data: GranularCoverageData) -> float:
        """Enhanced weight calculation with Authelia-specific and security-focused scoring"""
        base_weight = 1.0
        
        # Determine if this is a state-based coverage target (Go/Python)
        is_state_based = self.target_type in ('authelia', 'casdoor', 'ory_hydra', 'zitadel', 'authentik', 'simplelogin', 'nodeoidc', 'logto')
        coverage_compensation = 1.3 if is_state_based else 1.0  # Boost exploration for Go targets
        
        # 1. Success path bonus (higher for longer successful chains)
        success_indices = [i for i, (sym, res) in enumerate(zip(sequence, results))
                         if res == 'Success' and sym in ('TokenExchange', 'UserInfo', 'Introspect', 'PasswordGrant')]
        if success_indices:
            base_weight *= (1.5 + 0.3 * len(success_indices)) * coverage_compensation
        
        # 2. Coverage gain bonus (exponential for significant gains)
        coverage_gain = coverage_data.coverage_percentage - self.baseline_coverage.coverage_percentage
        if coverage_gain > 0:
            gain_multiplier = 1 + coverage_gain / 3
            if is_state_based:
                gain_multiplier *= 1.5  # Boost for less precise coverage
            base_weight *= gain_multiplier
        
        # 3. Module coverage bonus (prioritize under-covered modules)
        for module, coverage in coverage_data.module_coverage.items():
            baseline = self.baseline_coverage.module_coverage.get(module, 0)
            if coverage > baseline:
                if baseline < 30:  # Very under-covered module improved
                    base_weight *= 1.4 * coverage_compensation
                elif baseline < 50:
                    base_weight *= 1.2 * coverage_compensation
        
        # 4. Hot methods bonus
        new_hot_methods = coverage_data.hot_methods - self.baseline_coverage.hot_methods
        if new_hot_methods:
            base_weight *= (1 + len(new_hot_methods) / 5)
        
        # 5. SERVER ERROR BONUS - High priority for potential vulnerabilities
        server_errors = sum(1 for r in results if r == 'ServerError')
        if server_errors > 0:
            base_weight *= (2.0 + server_errors * 0.5) * coverage_compensation
        
        # 6. UNUSUAL STATUS CODE BONUS
        unusual_status = sum(1 for r in results if r.startswith('Status') and 
                           r not in ('Status302', 'Status303', 'Status400', 'Status401', 'Status403', 'Status404'))
        if unusual_status > 0:
            base_weight *= (1.5 + unusual_status * 0.3)
        
        # 7. SECURITY-CRITICAL SYMBOL BONUS (enhanced for Authelia)
        security_symbols = {
            'TokenBadCode', 'TokenWrongClientSecret', 'UserInfoWrongToken',
            'AuthorizeBadRedirectUri', 'AuthorizeNoPKCE', 'AuthorizeImplicit',
            'AuthorizeOpenRedirect', 'UseRefreshAsAccess', 'UseIDTokenAsAccess',
            'AuthorizeScopeEscalation', 'AuthorizeScopeAdmin', 'TokenExchangeWrongClient',
            # Authelia-specific security symbols
            'AutheliaFirstFactorBypass', 'Authelia2FABypass', 'AutheliaConsentBypass',
            'AutheliaSessionFixation', 'AutheliaRegulationBypass',
            # Casdoor-specific security symbols
            'CasdoorAutoSigninPasswordInURL', 'CasdoorSessionCookieFlags',
            'CasdoorTokenCorsOriginEcho', 'CasdoorUserinfoCorsOpen',
            'CasdoorAuthCodeReplay',
            # Ory Hydra-specific security symbols
            'HydraAdminAPIProbe', 'HydraClientCreation', 'HydraParFlood',
            # Zitadel-specific security symbols
            'ZitadelAPIProbe', 'ZitadelOrgContextConfusion',
            'ZitadelMFABypass', 'ZitadelTokenExchangeImpersonation',
        }
        security_hits = sum(1 for s in sequence if s in security_symbols)
        security_multiplier = 1 + security_hits * 0.25
        if is_state_based:
            security_multiplier *= 1.2  # Extra boost for Authelia security tests
        base_weight *= security_multiplier
        
        # 8. SUCCESSFUL ATTACK PATTERN DETECTION (critical findings)
        for sym, res in zip(sequence, results):
            if sym in security_symbols and res == 'Success':
                base_weight *= 3.0 * coverage_compensation  # Major boost for successful attack patterns
        
        # 9. Go-target-specific endpoint coverage bonus
        if is_state_based:
            target_endpoints = {
                'authelia': {'AutheliaFirstFactor', 'AutheliaSecondFactor',
                             'AutheliaConsent', 'AutheliaLogout', 'AutheliaState'},
                'casdoor': {'CasdoorAutoSigninPasswordInURL', 'CasdoorSessionCookieFlags',
                            'CasdoorTokenCorsOriginEcho', 'CasdoorUserinfoCorsOpen'},
                'ory_hydra': {'HydraAdminAPIProbe', 'HydraClientCreation', 'HydraParFlood'},
                'zitadel': {'ZitadelAPIProbe', 'ZitadelOrgContextConfusion',
                            'ZitadelMFABypass', 'ZitadelTokenExchangeImpersonation'},
            }.get(self.target_type, set())
            endpoint_hits = sum(1 for s in sequence if s in target_endpoints)
            if endpoint_hits > 0:
                base_weight *= (1 + endpoint_hits * 0.2)
        
        # 10. Response diversity bonus (especially important for Authelia)
        unique_results = len(set(results))
        if unique_results >= 3:
            diversity_bonus = 1 + (unique_results - 2) * 0.1
            if is_state_based:
                diversity_bonus *= 1.3
            base_weight *= diversity_bonus
        
        # 11. Penalty for excessive failures (but less harsh for Authelia)
        failure_ratio = sum(1 for r in results if r in ('BadRequest', 'UnknownSymbol', 'Status0')) / max(1, len(results))
        if failure_ratio > 0.8:
            base_weight *= (0.4 if is_state_based else 0.3)
        elif failure_ratio > 0.6:
            base_weight *= (0.6 if is_state_based else 0.5)
        elif failure_ratio > 0.4:
            base_weight *= (0.8 if is_state_based else 0.7)
        
        # 12. Sequence length bonus (longer successful sequences are valuable)
        if len(sequence) >= 5 and failure_ratio < 0.3:
            base_weight *= 1.2

        # 13. NEW — template-novelty penalty. Prevents the favored queue from
        # filling with N copies of "PasswordGrant→RefreshToken→RefreshToken".
        # Key on (symbol, result) bigrams so mutation parameters still vary.
        try:
            tmpl_key = tuple(zip(sequence, results))
            seen = self._template_counts.get(tmpl_key, 0)
            self._template_counts[tmpl_key] = seen + 1
            if seen >= 1:
                # 2nd copy 0.5, 3rd 0.25, 4th+ 0.1 — exponential damping.
                base_weight *= max(0.1, 0.5 ** seen)
        except Exception:
            pass

        # 14. NEW — probe-gain gate. If a seed produced zero new probes since
        # its parent, cap its weight so oracle-promoted-but-zero-coverage seeds
        # can never dominate favored selection.
        new_probes_this_seed = getattr(self, '_last_new_probes', None)
        if new_probes_this_seed is not None and new_probes_this_seed == 0:
            base_weight = min(base_weight, 2.0)
        
        return min(base_weight, 20.0)  # Higher ceiling for important findings

    def _generate_overrides(self, mutated_seq: List[str]) -> Dict:
        """Protocol-aware override generation (boofuzz fields + value tables).

        Extracted verbatim from the fuzz loop (P4). Subclasses may replace
        this wholesale (e.g. AblationFuzzer arm A6 byte-level mutation).
        """
        overrides = {}
        if self.boofuzz and self.boofuzz.is_available():
            try:
                overrides = self.boofuzz.generate_overrides()
                # 新增：低概率注入畸形字段（超长/NULL/CRLF/Unicode）
                if random.random() < 0.2:
                    malformed = self.boofuzz._make_malformed_fields()
                    # 注入到 Authorize
                    for k, v in malformed.items():
                        if k in ('state', 'nonce', 'redirect_uri', 'scope'):
                            overrides.setdefault('Authorize', {})[k] = v
                    # 注入到 Login（username/password）
                    if 'username' in malformed or 'password' in malformed:
                        overrides.setdefault('Login', {}).update({k: v for k, v in malformed.items() if k in ('username', 'password')})
            except Exception:
                overrides = {}
        # Added: 标准授权码序列下的保守变异与客户端认证多样化
        standard_flow = all(s in mutated_seq for s in ['Authorize', 'Login', 'AuthCodeRedirect', 'TokenExchange'])
        if standard_flow:
            te = overrides.get('TokenExchange', {})
            if isinstance(te, dict):
                te.pop('client_secret', None)  # 避免 invalid_client
                import random as _r
                te['client_auth'] = _r.choice(['post', 'basic'])
                # PKCE edge-case injection — ONLY for targets that support PKCE
                if self.profile.get('supports_pkce', False) and _r.random() < 0.1:
                    te['code_verifier'] = 'A' * _r.choice([10, 128, 512, 1000])
                # NEW: grant_type fuzzing — exercises the token
                # endpoint dispatcher (AccessTokenIssuer / grant
                # handler registry) with valid-but-unexpected or
                # slightly-malformed grant types.
                if _r.random() < 0.08:
                    te['grant_type'] = _r.choice([
                        'authorization_code ',                # trailing space
                        'AUTHORIZATION_CODE',                 # case confusion
                        'urn:ietf:params:oauth:grant-type:jwt-bearer',
                        'urn:ietf:params:oauth:grant-type:token-exchange',
                        'urn:ietf:params:oauth:grant-type:saml2-bearer',
                        'password',                           # wrong grant
                        'client_credentials',
                        '',                                   # empty
                    ])
                overrides['TokenExchange'] = te
            au = overrides.get('Authorize', {})
            if isinstance(au, dict):
                for k in ('redirect_uri', 'state', 'nonce'):
                    au.pop(k, None)  # 保持会话一致性
                import random as _r
                # PKCE plain method injection — ONLY for PKCE-capable targets
                if self.profile.get('supports_pkce', False) and _r.random() < 0.1:
                    au['code_challenge_method'] = 'plain'
                    try:
                        au['code_challenge'] = self.sut.oauth_protocol.code_verifier
                    except Exception:
                        au['code_challenge'] = 'A' * 64
                # NEW: WSO2 / OIDC extension-parameter probing at
                # the authorize endpoint. These live in the same
                # OAuth2AuthzEndpoint branch but touch code paths
                # the happy-path baseline never visits.
                if self.target_type == 'wso2' and _r.random() < 0.15:
                    au[_r.choice(['prompt', 'display', 'max_age',
                                  'acr_values', 'ui_locales'])] = _r.choice([
                        'none', 'login', 'consent', 'select_account',
                        'popup', 'page', 'touch', 'wap',
                        '0', '3600', '-1', 'A' * 256,
                        'urn:mace:incommon:iap:silver',
                        'en-US fr-CA zh-CN ja-JP',
                    ])
                overrides['Authorize'] = au
        # 为其他令牌端点注入 client_auth 多样化
        for sym in ('RefreshToken', 'RevokeToken', 'Introspect', 'ClientCredentials'):
            d = overrides.get(sym, {})
            if isinstance(d, dict):
                import random as _r
                d['client_auth'] = _r.choice(['post', 'basic'])
                overrides[sym] = d

        # NEW: WSO2 — deepen state exploration via per-symbol
        # payload rotation on the new attack endpoints.  This
        # keeps each iteration on the "extension surface" path
        # rather than re-hitting the baseline authorize branch.
        # (CVE-knowledge ablation: these payload tables are historical-
        # CVE-derived heuristics, gated by disable_cve_patterns.)
        import random as _r
        if self.target_type == 'wso2' and not self._disable_cve_patterns:
            if 'Wso2ScopeInjection' in mutated_seq and _r.random() < 0.8:
                overrides.setdefault('Wso2ScopeInjection', {})['scope'] = _r.choice([
                    'openid ' + 'A' * 8192,
                    "openid' OR 1=1--",
                    'openid\x00\x01\x02',
                    'openid\r\nX-Forwarded-For: 127.0.0.1',
                    'openid ' + ' '.join(f's{i}' for i in range(512)),
                    '../../../internal/admin',
                ])
            if 'Wso2RequestUriSSRF' in mutated_seq and _r.random() < 0.8:
                overrides.setdefault('Wso2RequestUriSSRF', {})['request_uri'] = _r.choice([
                    'http://169.254.169.254/latest/meta-data/',
                    'http://localhost:6300/',                           # JaCoCo port
                    'http://127.0.0.1/actuator/env',
                    'file:///etc/passwd',
                    'gopher://127.0.0.1:2181/_stat',
                    'http://internal.wso2/secret',
                    'http://[::1]:9443/carbon/admin/',
                ])
            if 'Wso2TenantConfusion' in mutated_seq and _r.random() < 0.8:
                overrides.setdefault('Wso2TenantConfusion', {})['tenant'] = _r.choice([
                    '../../carbon/admin',
                    '%252e%252e',
                    'a' * 512,
                    'tenant;drop table IDN_OAUTH',
                    '\x00admin',
                ])
            if 'Wso2PromptNone' in mutated_seq and _r.random() < 0.5:
                overrides.setdefault('Wso2PromptNone', {})['prompt'] = _r.choice([
                    'none', 'none login', 'NONE', 'none\x00',
                    'none consent', 'none select_account',
                ])

        # Cross-target wire-level mutations (D.1–D.5).
        # Originally WSO2-only, now generalized to all targets since
        # these exercise fundamental protocol edge cases.
        # (CVE-knowledge ablation: D.1–D.5 were distilled from the
        # historical-CVE pattern analysis — gated by disable_cve_patterns.)
        if not self._disable_cve_patterns:
            # D.1 — TokenExchange Content-Type poisoning
            if 'TokenExchange' in mutated_seq and _r.random() < 0.15:
                overrides.setdefault('TokenExchange', {})['content_type'] = _r.choice([
                    'application/xml',
                    'application/json',
                    'multipart/form-data; boundary=',
                    'application/x-www-form-urlencoded; charset=' + 'A' * 4096,
                    'application/',                 # no subtype
                    '/json',                         # no type
                    '',                              # empty
                    'application/x-www-form-urlencoded\r\nX-Injected: 1',
                    'application/json\x00application/xml',
                ])

            # D.2 — TokenExchange body flooding (5000 repeated params)
            if 'TokenExchange' in mutated_seq and _r.random() < 0.05:
                overrides.setdefault('TokenExchange', {})['extra_params'] = [
                    ('code', 'A' * 16) for _ in range(_r.choice([500, 2000, 5000]))
                ]

            # D.3 — UserInfo duplicate Authorization header
            if 'UserInfo' in mutated_seq and _r.random() < 0.10:
                overrides.setdefault('UserInfo', {})['duplicate_auth_header'] = True

            # D.4 — UserInfo fake-JWT probe (alg=none / expired)
            if 'UserInfo' in mutated_seq and _r.random() < 0.10:
                overrides.setdefault('UserInfo', {})['authorization'] = _r.choice([
                    # alg=none header, admin sub, empty signature
                    'Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJhZG1pbiJdfX0.',
                    # expired exp=1
                    'Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjF9.a',
                    # malformed 3-part
                    'Bearer foo.bar.baz',
                    # 16KB of noise
                    'Bearer ' + 'A' * 16384,
                ])

            # D.5 — Introspect pathological token values
            if 'Introspect' in mutated_seq and _r.random() < 0.15:
                overrides.setdefault('Introspect', {})['token'] = _r.choice([
                    '', ' ', 'deadbeef' * 8,
                    'foo\x00bar', 'foo\r\nbar',
                    'A' * 16384,
                    'eyJhbGciOiJub25lIn0.eyJleHAiOjF9.',
                ])
        return overrides


    # ==================================================================
    # P1/P2/P5 hooks — minimal overridable seams (default = legacy behavior)
    # ==================================================================

    def _evaluate_oracles(self, mutated_seq: List[str], results: List[str]) -> List[Dict]:
        """Security-oracle evaluation hook. Default = legacy inline behavior."""
        oracle_hits: List[Dict] = []
        try:
            if self.sut and self.sut.oauth_protocol:
                orc = SecurityOracles(self.sut.oauth_protocol)
                oracle_hits = orc.quick_oracle(mutated_seq, results, self.target_type)
                for hit in oracle_hits:
                    if hit.get('severity') in ('CRITICAL', 'HIGH'):
                        print(f"  🔴 [{hit['severity']}] {hit['type']}: {hit['detail']}")
        except Exception as e:
            oracle_hits = []
        return oracle_hits

    def _make_race_tester(self, oauth_cfg):
        """Race tester factory hook (adaptive/serialized variants override)."""
        return RaceConditionTester(oauth_cfg)

    def _run_race_probe(self, it: int, has_success_path: bool, race_tester) -> List[Dict]:
        """Barrier race-probe hook. Default = legacy behavior (N=5 every 50 iters)."""
        hits: List[Dict] = []
        if it % 50 == 0 and has_success_path and self.sut.oauth_protocol:
            proto = self.sut.oauth_protocol
            if proto.auth_code:
                try:
                    race_finding = race_tester.test_code_race(
                        auth_code=proto.auth_code,
                        token_endpoint=proto.token_endpoint,
                        client_id=proto.config.client_id,
                        client_secret=proto.config.client_secret,
                        redirect_uri=proto.config.redirect_uri,
                        code_verifier=proto.code_verifier,
                        num_requests=5
                    )
                    if race_finding:
                        hits.append(race_finding)
                        print(f"[RACE] Code race condition detected!")
                except Exception:
                    pass

            if proto.refresh_token_value:
                try:
                    refresh_race = race_tester.test_refresh_race(
                        refresh_token=proto.refresh_token_value,
                        token_endpoint=proto.token_endpoint,
                        client_id=proto.config.client_id,
                        client_secret=proto.config.client_secret,
                        num_requests=5
                    )
                    if refresh_race:
                        hits.append(refresh_race)
                        print(f"[RACE] Refresh token race condition detected!")
                except Exception:
                    pass
        return hits


    def _oracle_weight_boost(self, oracle_hits):
        """Oracle-driven weight inflation for newly appended sequences (P8 hook).
        Default = legacy behavior; arms that remove oracle feedback override
        this to 0.0 so oracle signals cannot steer scheduling."""
        try:
            oracle_severity_weight = {'CRITICAL': 5.0, 'HIGH': 3.0, 'MEDIUM': 1.5, 'LOW': 0.5}
            return 0.4 * sum(oracle_severity_weight.get(o.get('severity', 'LOW'), 0.5)
                             for o in oracle_hits)
        except Exception:
            return 0.0

    def _emit_iteration_events(self, it: int, mutated_seq: List[str], results: List[str],
                               oracle_hits: List[Dict], granular_coverage) -> None:
        """Per-iteration event hook (metrics sinks / boundary-engagement logs).

        Default no-op; OAuthLancer's metrics.MetricsSink overrides this.
        """
        return None

    def fuzz(self, iterations: int = 200):
        # 初始化基线细粒度覆盖率
        self.baseline_coverage = self._dump_and_update_granular_coverage(force=True)
        self.initial_baseline_coverage = GranularCoverageData()
        self.initial_baseline_coverage.coverage_percentage = self.baseline_coverage.coverage_percentage
        self.initial_baseline_coverage.instructions_covered = self.baseline_coverage.instructions_covered
        self.initial_baseline_coverage.instructions_total = self.baseline_coverage.instructions_total
        self.initial_baseline_coverage.lines_covered = self.baseline_coverage.lines_covered
        self.initial_baseline_coverage.lines_total = self.baseline_coverage.lines_total
        self.initial_baseline_coverage.branches_covered = self.baseline_coverage.branches_covered
        self.initial_baseline_coverage.branches_total = self.baseline_coverage.branches_total
        
        # Initialize race condition tester
        oauth_cfg = self.config.get('oauth', {})
        race_tester = self._make_race_tester(oauth_cfg)

        # Get Go coverage manager for Go targets (Authelia, Casdoor, Ory Hydra, Zitadel)
        go_cov = getattr(self, 'go_coverage', None)
        if go_cov is None:
            mgr = getattr(self, 'authelia_manager', None) or getattr(self, 'target_manager', None)
            if mgr:
                go_cov = getattr(mgr, 'go_coverage', None)

        print(f"[DEBUG] Fuzzer: target_type={self.target_type}, go_cov={go_cov is not None}, corpus_size={len(self.corpus)}")
        
        for it in range(int(iterations or 0)):
            # P3: equal-budget stop counted in protocol steps (execution_count).
            # 0 = unlimited (legacy behavior).
            if self._budget_protocol_steps and self.execution_count >= self._budget_protocol_steps:
                print(f"[Budget] reached {self.execution_count} protocol steps "
                      f"(budget={self._budget_protocol_steps}) at it={it}; stopping.")
                break
            base_idx = self._choose_base_sequence()
            # Force first 5 iterations to cycle through core success flows
            # so we immediately build coverage breadth before mutation takes over.
            if it < 5 and it < len(self.corpus):
                base_idx = it
            base_seq = self.corpus[base_idx]
            mutated_seq = self._mutate_sequence(base_seq)

            # 仅内部序列，无外部 Selenium
            overrides = self._generate_overrides(mutated_seq)
            # Execute sequence and track responses for coverage
            self.sut.set_symbol_overrides(overrides)
            self.sut.reset()

            # P0: best-effort per-sequence cookie reset for the underlying
            # requests.Session AFTER sut.reset() rebuilt it.  reset()
            # already constructs a fresh Session in protocol/base.py, but
            # some target mixins (WSO2) retain non-Session state that
            # must be cleared too.  We call the WSO2 reset helper if
            # available — a no-op on other targets.
            try:
                proto = self.sut.oauth_protocol
                if hasattr(proto, '_wso2_reset_state'):
                    proto._wso2_reset_state()
            except Exception:
                pass

            results = []
            security_alerts = []  # Track security alerts for this sequence

            # Determine logging verbosity based on iteration count and interestingness
            # Log: first 3 iterations, every 50th, and sequences with security symbols
            has_security_symbol = any(s in mutated_seq for s in 
                ['AuthorizeOpenRedirect', 'AuthorizeScopeEscalation', 'AuthorizeScopeAdmin',
                 'TokenExchangeWrongClient', 'AutheliaFirstFactorBypass', 'Authelia2FABypass',
                 'AuthorizeRedirectSSRF', 'UseIDTokenAsAccess', 'UseRefreshAsAccess'])
            should_log_sequence = (it < 3) or (it % 50 == 0) or has_security_symbol
            
            if should_log_sequence:
                print(f"\n--- Seq #{it} [{len(mutated_seq)} steps] ---")
            
            for idx, symbol in enumerate(mutated_seq):
                result = self.sut.step(symbol)
                results.append(result)
                
                # Build display string with mutation tags
                tags = []
                if hasattr(self.sut, '_mutation_tags'):
                    tags = self.sut._mutation_tags(symbol)
                tag_str = f"[{','.join(tags)}]" if tags else ""
                
                # Get mutation details if available
                detail = ""
                if hasattr(self.sut, '_mutation_detail'):
                    detail = self.sut._mutation_detail(symbol)
                
                # === ENHANCED SECURITY-AWARE LOGGING ===
                # Check for security anomalies based on symbol+result combination
                security_alert = None
                
                if result in ('Success', 'Created'):
                    indicator = "✓"
                    # Check if this success is potentially dangerous
                    security_alert = self._check_security_anomaly(symbol, result)
                elif result == 'Redirect':
                    indicator = "→"
                    # Check if this redirect is security-relevant.
                    # The real requests.Response is cached on the SUT by
                    # OAuthMapper/OAuthSUT.execute_symbol as _last_response.
                    security_alert = self._check_redirect_security(
                        symbol, result,
                        getattr(self.sut, '_last_response', None),
                    )
                elif result.startswith('Status0') or result == 'UnknownSymbol':
                    indicator = "✗"
                elif result in ('Unauthorized', 'Forbidden', 'BadRequest'):
                    indicator = "!"
                else:
                    indicator = "·"
                    # Check for unusual status codes
                    security_alert = self._check_unusual_status(symbol, result)
                
                # Log step result in clean format
                if should_log_sequence:
                    print(f"  {indicator} {symbol}{tag_str} -> {result}")
                    
                    # Print mutation details on next line if present and meaningful
                    if detail and detail != 'client_auth=post':
                        print(f"      └─ {detail}")
                    
                    # Print security alert if detected
                    if security_alert:
                        self._log_security_alert(security_alert, go_cov)
                        security_alerts.append(security_alert)
                
                # Track response in Go coverage manager for state-based targets
                if go_cov and self.target_type in ('authelia', 'casdoor', 'ory_hydra', 'zitadel', 'authentik', 'simplelogin', 'nodeoidc', 'logto'):
                    try:
                        proto = self.sut.oauth_protocol
                        if proto and proto.received_data:
                            last_resp = proto.received_data[-1]
                            go_cov.track_response(last_resp, endpoint=symbol)
                    except Exception:
                        pass
            
            # Summary of security alerts for this sequence
            if security_alerts and should_log_sequence:
                critical_count = sum(1 for a in security_alerts if a.get('severity') == 'CRITICAL')
                high_count = sum(1 for a in security_alerts if a.get('severity') == 'HIGH')
                if critical_count > 0 or high_count > 0:
                    print(f"  🔒 Security Summary: {critical_count} CRITICAL, {high_count} HIGH alerts")

            self.sut.set_symbol_overrides({})

            self.execution_count += len(mutated_seq)
            self.mutation_count += 1

            # 新增：检查服务端进程健康状态
            server_alive, crash_reason = self.health_monitor.check_process_alive()
            crash_signals = []
            if not server_alive:
                print(f"[CRITICAL] Keycloak container crashed! Reason: {crash_reason}")
                # 抓取崩溃日志与退出码
                exit_code = self.health_monitor.get_exit_code()
                oom_killed = self.health_monitor.check_oom_killed()
                logs = ''
                try:
                    if self.kc_manager:
                        logs = self.kc_manager.get_recent_logs(tail=500, keywords=[])
                        crash_signals = self.health_monitor.extract_crash_signals(logs)
                except Exception:
                    pass
                # 记录崩溃事件到 interesting_cases
                crash_case = {
                    'timestamp': time.time(),
                    'execution_count': self.execution_count,
                    'response': {'status_code': 'CRASH'},
                    'crash_detail': {
                        'reason': crash_reason,
                        'exit_code': exit_code,
                        'oom_killed': oom_killed,
                        'crash_signals': crash_signals
                    },
                    'sequence': mutated_seq,
                    'overrides': overrides,
                    'keycloak_logs': (logs or '')[:8000],
                    'oracles': [{'type': 'SERVER_CRASH', 'detail': crash_reason, 'severity': 'CRITICAL'}]
                }
                if self._save_interesting_cases:
                    self.interesting_cases.append(crash_case)
                # 提升该序列权重（优先复现）—— feedback-off arm keeps corpus frozen
                if not self._disable_feedback:
                    self.corpus.append(mutated_seq)
                    self.selection_weights.append(10.0)  # 极高权重
                    self.favored_flags.append(True)  # Always favor crash-producing seeds
                print(f"[CRASH] Sequence: {mutated_seq}")
                print(f"[CRASH] Signals: {crash_signals}")
                # 停止 fuzzing，保存现场
                break

            # 获取细粒度覆盖率数据
            # granular_coverage = self._dump_and_update_granular_coverage()

            state_pairs = [f"{sym}:{res}" for sym, res in zip(mutated_seq, results)]
            state_signature = f"{'|'.join(state_pairs)}:{len(mutated_seq)}"
            is_new_state = state_signature not in self.seen_state_signatures
            
            # 动态决定是否 dump 覆盖：新状态/成功路径/周期触发
            has_success_path = any(
                (sym in ('TokenExchange', 'UserInfo', 'Introspect') and res == 'Success')
                for sym, res in zip(mutated_seq, results)
            )

            effective_dump_interval = self.dump_interval
            do_dump = (it % effective_dump_interval == 0) or (has_success_path and it < 10) or is_new_state

            granular_coverage = self._dump_and_update_granular_coverage(force=do_dump)
            # Expose last differential for downstream weight/oracle logic
            self._last_differential_coverage = granular_coverage

            # Run streamlined security oracle for vulnerability detection
            oracle_hits = self._evaluate_oracles(mutated_seq, results)

            # Race condition testing (periodically, on successful token flows)
            oracle_hits.extend(self._run_race_probe(it, has_success_path, race_tester))

            # P5: per-iteration event hook (metrics sinks; default no-op)
            self._emit_iteration_events(it, mutated_seq, results, oracle_hits, granular_coverage)

            # === Replaced dump-interval escalation with gentle pulse ===
            cov_gain = granular_coverage.coverage_percentage - self.baseline_coverage.coverage_percentage
            if do_dump:
                if cov_gain >= 0.1 or (granular_coverage.hot_methods and
                                       (granular_coverage.hot_methods - self.baseline_coverage.hot_methods)):
                    self.no_gain_rounds = 0
                else:
                    self.no_gain_rounds += 1

            has_granular_coverage_gain = self._has_granular_coverage_gain(granular_coverage)
            bad_ratio = (
                sum(1 for r in results if r in ('BadRequest', 'UnknownSymbol', 'Status0'))
                / max(1, len(results))
            )

            interesting_now = self._is_interesting(
                has_coverage_gain=has_granular_coverage_gain,
                is_new_state=is_new_state,
                results=results,
                symbols=mutated_seq,
                oracle_hits=oracle_hits,
            )

            appended = False
            if interesting_now:
                self.seen_state_signatures.add(state_signature)
                # Feedback-off arm: record the case (detection metrics) but
                # keep the corpus frozen — no promotion, no weight updates.
                if not self._disable_feedback:
                    self.corpus.append(mutated_seq)
                    base_w = self._calculate_sequence_weight(mutated_seq, results, granular_coverage)
                    base_w *= (1.0 + self._oracle_weight_boost(oracle_hits))

                    self.selection_weights.append(min(base_w, 50.0))
                    protocol_500 = any(
                        r == 'ServerError' and s in (
                            'TokenExchange', 'TokenBadCode', 'TokenWrongClientSecret',
                            'TokenExchangeWrongClient', 'TokenExchangeParamFlood',
                            'Introspect', 'IntrospectMalformed', 'IntrospectEmptyToken',
                            'RevokeToken', 'RefreshToken',
                            'PasswordGrant', 'ClientCredentials',
                        )
                        for s, r in zip(mutated_seq, results)
                    )
                    self.favored_flags.append(
                        bool(has_granular_coverage_gain) or bool(oracle_hits) or protocol_500
                    )
                    appended = True

                    # Limit corpus size to prevent memory issues
                    MAX_CORPUS_SIZE = 1000
                    if len(self.corpus) > MAX_CORPUS_SIZE:
                        # Prefer removing non-favored low-weight seeds first
                        sorted_indices = sorted(
                            range(len(self.selection_weights)),
                            key=lambda i: (self.favored_flags[i] if i < len(self.favored_flags) else False,
                                           self.selection_weights[i])
                        )
                        remove_count = len(self.corpus) - MAX_CORPUS_SIZE
                        for idx in sorted_indices[:remove_count]:
                            if idx < len(self.corpus):
                                self.corpus.pop(idx)
                                self.selection_weights.pop(idx)
                                if idx < len(self.favored_flags):
                                    self.favored_flags.pop(idx)

                last_status = results[-1] if results else 'ERROR'
                case = {
                    'timestamp': time.time(),
                    'execution_count': self.execution_count,
                    'response': {'status_code': last_status},
                    'coverage': {
                        'coverage_percentage': granular_coverage.coverage_percentage,
                        'module_coverage': granular_coverage.module_coverage,
                        'hot_methods': list(granular_coverage.hot_methods),
                        'global_probe_set_size': len(self._global_probe_set),
                    },
                    'state_signature': state_signature,
                    'sequence': mutated_seq,
                    'overrides': overrides,
                    'oracles': oracle_hits
                }
                if (self.kc_manager and (last_status in ('ServerError',) or oracle_hits)):
                    try:
                        logs = self.kc_manager.get_recent_logs(
                            tail=300,
                            keywords=['ERROR', 'Exception', 'IllegalArgument', 'NullPointer', 'IllegalState', 'MediaTypeHeaderDelegate', 'StackTrace', 'OutOfMemory', 'StackOverflow']
                        )
                        case['keycloak_logs'] = (logs or '')[:4000]
                        crash_sigs = self.health_monitor.extract_crash_signals(logs)
                        if crash_sigs:
                            case['crash_signals'] = crash_sigs
                            oracle_hits.append({'type': 'POTENTIAL_CRASH', 'detail': f'crash_signals={crash_sigs}', 'severity': 'HIGH'})
                    except Exception:
                        pass
                if self._save_interesting_cases:
                    self.interesting_cases.append(case)

            self._update_selection_weights(
                is_new_state,
                selected_idx=base_idx,
                gave_coverage=has_granular_coverage_gain,
                oracle_hit=bool(oracle_hits),
            )

            self._maybe_refresh_baseline(granular_coverage)

            if it % 20 == 0:
                crashes = sum(1 for c in self.interesting_cases if 'crash_detail' in c or 'crash_signals' in c)
                critical_findings = sum(1 for c in self.interesting_cases
                                       for o in c.get('oracles', []) if o.get('severity') == 'CRITICAL')

                success_steps = sum(1 for r in results if r in ('Success', 'Redirect', 'Created'))
                error_steps = sum(1 for r in results if r.startswith('Status0') or r == 'UnknownSymbol')
                auth_failures = sum(1 for r in results if r in ('Unauthorized', 'Forbidden'))

                favored_count = sum(1 for f in self.favored_flags if f)
                # Display CUMULATIVE coverage (self.current_coverage) for progress tracking,
                # not the per-iteration differential which is often 0.
                display_cov = self.current_coverage.coverage_percentage if self.current_coverage else 0.0
                print(f"\n[OAuthFuzz] it={it}, corpus={len(self.corpus)}, favored={favored_count}, "
                      f"new_states={len(self.seen_state_signatures)}, interesting={len(self.interesting_cases)}, "
                      f"crashes={crashes}, critical={critical_findings}, "
                      f"cov={display_cov:.2f}%, "
                      f"probes={len(self._global_probe_set)}, stagnant={self._stagnant_probe_rounds}")

                if results:
                    outcome_summary = f"last_seq: {success_steps}✓ {auth_failures}! {error_steps}✗"
                    print(f"  {outcome_summary} of {len(results)} steps")


# Backward-compatible alias
AFLNetMinimalFuzzer = OAuthFuzzMinimalFuzzer  # backward compat
