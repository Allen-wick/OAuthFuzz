#!/usr/bin/env python3
"""
Configuration dataclasses for OAuth fuzzing framework.
Centralizes all configuration structures used across modules.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class OAuthConfig:
    """OAuth protocol configuration for any target."""
    base_url: str
    realm: str
    client_id: str
    client_secret: Optional[str]
    redirect_uri: str
    username: str
    password: str
    scope: str = "openid profile email"
    target_type: str = "keycloak"
    # OIDC-compliant targets may specify an issuer different from base_url
    issuer: Optional[str] = None
    # explicit overrides when discovery doc is unavailable
    discovery_url: Optional[str] = None

@dataclass
class FuzzerConfig:
    """Fuzzing session configuration."""
    iterations: int = 1000
    mode: str = "aflnet"
    adapter: str = "none"
    dump_every_n: int = 10
    max_corpus_size: int = 1000
    security_mode: bool = False
    canonicalize_sequences: bool = True

@dataclass
class CoverageConfig:
    """Coverage collection configuration."""
    agent_port: int = 6300
    includes: List[str] = field(default_factory=list)
    excludes: List[str] = field(default_factory=list)
    work_dir: str = "jacoco_tools"
    version: str = "0.8.14"

@dataclass
class TargetConfig:
    """Target server configuration."""
    container_name: str = ""
    image: str = ""
    port: int = 8080
    health_endpoint: str = "/login"
    startup_timeout: int = 120

@dataclass
class SpringAuthzConfig:
    """Spring Authorization Server specific config."""
    container_name: str = "sas-fuzz"
    image: str = "sas-fuzz:latest"           # built locally, see spring_authz_manager.py
    http_port: int = 9000
    config_dir: str = "./sas_config"
    work_dir: str = "./sas_work"
    startup_timeout: int = 180
    jacoco_enabled: bool = True
    # Which demo sample to build from in the SAS source tree
    sample_module: str = "samples/demo-authorizationserver"

@dataclass
class CxfOAuthConfig:
    """Apache CXF rs-security-oauth2 specific config."""
    container_name: str = "cxf-oauth-fuzz"
    image: str = "cxf-oauth:latest"
    http_port: int = 8081
    config_dir: str = "./cxf_config"
    work_dir: str = "./cxf_work"
    startup_timeout: int = 120
    jacoco_enabled: bool = True

@dataclass
class Wso2Config:
    """WSO2 Identity Server config."""
    container_name: str = "wso2is-fuzz"
    image: str = "wso2/wso2is:7.0.0"
    https_port: int = 9443
    http_port: int = 9763
    config_dir: str = "./wso2_config"
    work_dir: str = "./wso2_work"
    startup_timeout: int = 300
    # WSO2 ships JaCoCo-compatible but not pre-instrumented — agent must be bootstrapped
    jacoco_enabled: bool = True
    admin_username: str = "admin"
    admin_password: str = "admin"
