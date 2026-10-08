#!/usr/bin/env python3
"""
Generate the audit harness configuration for Authelia multi-round security testing.

Produces:
  config/configuration.yml  - 4 OIDC clients (fuzz-client, fuzz-preconf, fuzz-public, fuzz-client2)
                               + access_control rules exercising the authz engine (wildcard, {group},
                               deny/private, bypass/public) + relaxed regulation for testing.
  config/users_database.yml - testuser + victim (argon2id).

Runs the *stock* Docker image directly (NOT via authelia_manager, which regenerates a
single-client config on every start). See start_container.sh.
"""
import os, sys, subprocess, base64, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = os.path.join(HERE, "config")
PEM = os.path.join(CFG, "oidc_jwks.pem")

# ---- secrets (stable across restarts so storage encryption key matches the DB) ----
SESSION_SECRET  = "7a8f9f23f784cce4d0b68cafd5a584fdcb20f313bab08f656f6e0b905c801953"
STORAGE_KEY     = "f761ac0b964a61a175dee075df5dfb3a9fd5056990ec5e0d86806c34e4cc425b"
HMAC_SECRET     = "bd9fe7f0d75e80a75c778463f1eb51d516e16f41021ec0bd2a38c6a43308996b"
JWT_RESET_SECRET= "d82e08c0099a6fc3d9d3bf4af1dceeb3f42b1ba8412468c230b0e060c4e0cb32"


def argon2_hash(password: str) -> str:
    try:
        from argon2 import PasswordHasher
        from argon2.profiles import RFC_9106_LOW_MEMORY
        return PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY).hash(password)
    except ImportError:
        pass
    # docker fallback
    try:
        r = subprocess.run(["docker", "run", "--rm", "authelia/authelia:latest",
                            "authelia", "crypto", "hash", "generate", "argon2",
                            "--password", password],
                           capture_output=True, text=True, timeout=60)
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("Digest:"):
                return line.split(":", 1)[1].strip()
            if line.startswith("$argon2"):
                return line
    except Exception as e:
        print("docker hash fallback failed:", e, file=sys.stderr)
    raise SystemExit("cannot generate argon2 hash; pip install argon2-cffi")


def build_config():
    with open(PEM) as f:
        pem = f.read().strip()

    return {
        "theme": "light",
        "server": {
            "address": "tcp://0.0.0.0:9091/",
            "buffers": {"read": 4096, "write": 4096},
            "timeouts": {"read": "6s", "write": "6s", "idle": "30s"},
            "endpoints": {"enable_pprof": False, "enable_expvars": False},
            "disable_healthcheck": False,
            "tls": {"key": "/config/server.key", "certificate": "/config/server.crt"},
        },
        "log": {"level": "debug", "format": "text", "file_path": "/data/authelia.log", "keep_stdout": True},
        "totp": {"disable": False, "issuer": "authelia.com", "period": 30, "skew": 1},
        "webauthn": {"disable": False, "display_name": "Authelia Fuzzing",
                     "attestation_conveyance_preference": "indirect",
                     "selection_criteria": {"user_verification": "preferred"}, "timeout": "60s"},
        "identity_validation": {"reset_password": {"jwt_secret": JWT_RESET_SECRET}},
        "authentication_backend": {
            "file": {
                "path": "/config/users_database.yml", "watch": False,
                "search": {"email": False, "case_insensitive": False},
                "password": {"algorithm": "argon2", "argon2": {
                    "variant": "argon2id", "iterations": 3, "memory": 65536,
                    "parallelism": 4, "key_length": 32, "salt_length": 16}},
            }
        },
        "access_control": {
            "default_policy": "deny",
            "rules": [
                # keep OIDC/API reachable
                {"domain": ["127.0.0.1"], "policy": "bypass",
                 "resources": ["^/api/health$", "^/api/oidc/.*", "^/api/state$", "^/api/configuration$"]},
                # A2 path-normalization probes on 127.0.0.1
                {"domain": ["127.0.0.1"], "policy": "bypass", "resources": ["^/public/.*$"]},
                {"domain": ["127.0.0.1"], "policy": "deny",   "resources": ["^/private/.*$"]},
                # A4 resource-regex anchoring probe (intentionally unanchored end) on 127.0.0.1
                {"domain": ["127.0.0.1"], "policy": "deny",   "resources": ["^/sec"]},
                # A3 wildcard-suffix probes (reachable via cookie domain example.test)
                {"domain": ["*.test"], "policy": "bypass"},          # foo.example.test -> bypass
                {"domain": ["secure.test"], "policy": "deny"},       # exact deny control
                # A3 canonical apex test: *.example.com (one_factor) vs example.com apex (deny)
                {"domain": ["*.example.com"], "policy": "one_factor"},
                {"domain": ["example.com"], "policy": "deny"},
                # group wildcard (A1: proven unreachable, kept for completeness)
                {"domain": ["{group}.test"], "policy": "one_factor"},
                # catch-alls on configured cookie domains
                {"domain": ["127.0.0.1"], "policy": "one_factor"},
                {"domain": ["example.test"], "policy": "one_factor"},
                {"domain": ["example.com"], "policy": "one_factor"},
            ],
        },
        "session": {
            "name": "authelia_session", "secret": SESSION_SECRET, "same_site": "lax",
            "expiration": "1h", "inactivity": "5m", "remember_me": "1M",
            "cookies": [
                {"domain": "127.0.0.1", "authelia_url": "https://127.0.0.1:9091",
                 "default_redirection_url": "https://127.0.0.1:7777"},
                {"domain": "example.test", "authelia_url": "https://auth.example.test:9091",
                 "default_redirection_url": "https://app.example.test:7777"},
                {"domain": "example.com", "authelia_url": "https://auth.example.com:9091",
                 "default_redirection_url": "https://app.example.com:7777"},
            ],
        },
        # relaxed so repeated PoC attempts are not banned mid-testing
        "regulation": {"max_retries": 1000, "find_time": "2m", "ban_time": "1h"},
        "storage": {"encryption_key": STORAGE_KEY, "local": {"path": "/data/db.sqlite3"}},
        "notifier": {"disable_startup_check": True, "filesystem": {"filename": "/data/notification.txt"}},
        "identity_providers": {
            "oidc": {
                "hmac_secret": HMAC_SECRET,
                "jwks": [{"key_id": "fuzz-key-1", "algorithm": "RS256", "use": "sig", "key": pem}],
                "cors": {"endpoints": ["authorization", "token", "revocation", "introspection", "userinfo"],
                         "allowed_origins_from_client_redirect_uris": True},
                "clients": [
                    # C1: existing confidential client, PKCE optional, implicit consent
                    {"client_id": "fuzz-client", "client_name": "OAuth Fuzzing Client",
                     "client_secret": "$plaintext$fuzz-client-secret", "public": False,
                     "authorization_policy": "one_factor", "require_pkce": False,
                     "pkce_challenge_method": "S256",
                     "redirect_uris": ["https://127.0.0.1:7777/callback"],
                     "scopes": ["openid", "profile", "email", "groups", "offline_access"],
                     "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
                     "response_types": ["code"],
                     "response_modes": ["form_post", "query", "fragment"],
                     "token_endpoint_auth_method": "client_secret_post",
                     "userinfo_signed_response_alg": "none", "consent_mode": "implicit"},
                    # pre-configured consent client (O6 de-risk)
                    {"client_id": "fuzz-preconf", "client_name": "PreConfig Consent Client",
                     "client_secret": "$plaintext$fuzz-preconf-secret", "public": False,
                     "authorization_policy": "one_factor", "consent_mode": "pre-configured",
                     "pre_configured_consent_duration": "30 days",
                     "redirect_uris": ["https://127.0.0.1:7777/callback"],
                     "scopes": ["openid", "profile", "groups", "offline_access"],
                     "grant_types": ["authorization_code", "refresh_token"],
                     "response_types": ["code"],
                     "token_endpoint_auth_method": "client_secret_post"},
                    # public client, PKCE required (O4/O5 boundary tests)
                    {"client_id": "fuzz-public", "client_name": "Public PKCE Client",
                     "public": True, "authorization_policy": "one_factor",
                     "require_pkce": True, "pkce_challenge_method": "S256",
                     "redirect_uris": ["http://127.0.0.1:8888/callback", "http://localhost:8888/callback"],
                     "scopes": ["openid", "profile", "email", "offline_access"],
                     "grant_types": ["authorization_code", "refresh_token"],
                     "response_types": ["code"],
                     "token_endpoint_auth_method": "none"},
                    # 2nd confidential client (O4 subject cross-client)
                    {"client_id": "fuzz-client2", "client_name": "Second Confidential Client",
                     "client_secret": "$plaintext$fuzz-client2-secret", "public": False,
                     "authorization_policy": "one_factor", "consent_mode": "implicit",
                     "redirect_uris": ["https://127.0.0.1:7778/callback"],
                     "scopes": ["openid", "profile", "email", "offline_access"],
                     "grant_types": ["authorization_code", "refresh_token"],
                     "response_types": ["code"],
                     "token_endpoint_auth_method": "client_secret_post"},
                ],
            }
        },
    }


def build_users():
    return {
        "users": {
            "testuser": {"disabled": False, "displayname": "Test User",
                         "password": argon2_hash("testpass"),
                         "email": "testuser@example.com", "groups": ["users", "dev"]},
            "victim": {"disabled": False, "displayname": "Victim User",
                       "password": argon2_hash("victimpass"),
                       "email": "victim@example.com", "groups": ["users"]},
        }
    }


def main():
    import yaml
    os.makedirs(CFG, exist_ok=True)
    with open(os.path.join(CFG, "configuration.yml"), "w") as f:
        yaml.dump(build_config(), f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=1000)
    with open(os.path.join(CFG, "users_database.yml"), "w") as f:
        yaml.dump(build_users(), f, default_flow_style=False, allow_unicode=True, sort_keys=False, width=1000)
    print("wrote", os.path.join(CFG, "configuration.yml"))
    print("wrote", os.path.join(CFG, "users_database.yml"))


if __name__ == "__main__":
    main()
