#!/usr/bin/env python3
"""
Logto Manager for OAuth Fuzzing Framework.

Manages Logto (TypeScript/Node.js OIDC provider) multi-container Docker
Compose lifecycle and operations.

Logto is a modern identity platform built on Node.js with PostgreSQL as its
database. It uses a React SPA for login/consent interactions. Endpoints are
mounted under the /oidc/ prefix.

Coverage collection uses GoCoverageManager in state-based tracking mode
to record endpoint coverage and error classification (TypeScript cannot
use JaCoCo).
"""

import subprocess
import time
import json
import os
import sys
import secrets
import requests
from typing import Dict, Optional, List

from targets_manager.base import TargetManager
from core.paths import PROJECT_ROOT


class LogtoManager(TargetManager):
    """
    Logto server manager for OAuth fuzzing.

    Manages a multi-container Docker Compose deployment consisting of:
      - PostgreSQL 17-alpine (database)
      - Logto server (OIDC provider + admin API)

    Ports:
      - 3001: OIDC endpoint (/oidc/auth, /oidc/token, etc.)
      - 3002: Admin API + console

    Configuration is performed via the Logto Management API after startup.
    """

    def __init__(self, config: Dict):
        super().__init__(config)

        cfg = config.get('logto', {})
        oauth_cfg = config.get('oauth', {})

        self.http_port = cfg.get('http_port', 3001)
        self.admin_port = cfg.get('admin_port', 3002)
        self.pg_port = cfg.get('pg_port', 54322)

        self.base_url = oauth_cfg.get('base_url', f'http://127.0.0.1:{self.http_port}')
        self.container_name = cfg.get('container_name', 'logto-fuzz')
        self.image = cfg.get('image', 'svhd/logto:latest')

        self.startup_timeout = cfg.get('startup_timeout', 180)

        self.config_dir = os.path.abspath(cfg.get('config_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'logto_service', 'config')))
        self.work_dir = os.path.abspath(cfg.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'logto_service', 'work')))
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)

        self.compose_path = os.path.join(self.config_dir, 'docker-compose.yml')
        self.env_path = os.path.join(self.config_dir, '.env')

        # Generated secrets
        self.pg_password = secrets.token_hex(16)
        self.oidc_cookie_keys = json.dumps([secrets.token_hex(32)])

        self.admin_email = cfg.get('admin_email', 'admin@fuzz.local')
        self.admin_password = cfg.get('admin_password', 'AdminPass2025!')

        # Endpoints (all under /oidc/ prefix)
        self.auth_endpoint       = f"http://127.0.0.1:{self.http_port}/oidc/auth"
        self.token_endpoint      = f"http://127.0.0.1:{self.http_port}/oidc/token"
        self.userinfo_endpoint   = f"http://127.0.0.1:{self.http_port}/oidc/me"
        self.introspect_endpoint = f"http://127.0.0.1:{self.http_port}/oidc/token/introspection"
        self.revoke_endpoint     = f"http://127.0.0.1:{self.http_port}/oidc/token/revocation"
        self.jwks_endpoint       = f"http://127.0.0.1:{self.http_port}/oidc/jwks"
        self.discovery_endpoint  = f"http://127.0.0.1:{self.http_port}/oidc/.well-known/openid-configuration"
        self.health_check_url    = f"http://127.0.0.1:{self.http_port}/oidc/.well-known/openid-configuration"

        # State-based coverage via NodeCoverageManager (Node.js/TypeScript-specific)
        try:
            from targets_manager.node_coverage_manager import NodeCoverageManager, LogtoErrorPatterns
            self.go_coverage = NodeCoverageManager(
                work_dir=os.path.join(self.config_dir, 'coverage'),
                container_name=self.container_name,
                base_url=self.base_url,
            )
            self.go_coverage.error_patterns = LogtoErrorPatterns
        except ImportError as e:
            print(f"[Logto] node_coverage_manager.py import failed: {e}")
            self.go_coverage = None

        self.jacoco = None

    # ── Lifecycle ────────────────────────────────────────────────────

    def start(self) -> bool:
        print("=" * 70)
        print("Starting Logto (Node.js OIDC provider)...")
        print(f"Image: {self.image}")
        print("=" * 70)

        try:
            self._cleanup_containers()

            for f in (self.compose_path, self.env_path):
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except Exception:
                        pass

            self._generate_compose_file()
            self._generate_env_file()

            print(f"Running docker compose up with {self.compose_path}...")
            result = subprocess.run(
                ['docker', 'compose', '-f', self.compose_path, 'up', '-d'],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode != 0:
                print(f"[Logto] docker compose up failed: {result.stderr}")
                return False
            print("[Logto] Docker compose services started")

            if not self._wait_for_logto(self.startup_timeout):
                print("[Logto] Failed to become healthy within timeout")
                self._print_compose_logs()
                return False

            # Attempt API config; don't block startup on failure
            if not self._configure_via_api():
                print("[Logto] Warning: API configuration failed (endpoints may still work)")

            print(f"[Logto] Ready at {self.base_url}")
            return True

        except subprocess.TimeoutExpired:
            print("[Logto] docker compose up timed out")
            return False
        except Exception as e:
            print(f"[Logto] Failed to start: {e}")
            import traceback
            traceback.print_exc()
            return False

    def stop(self) -> None:
        print("[Logto] Stopping...")
        self._cleanup_containers()
        print("[Logto] Stopped")

    def is_healthy(self) -> bool:
        try:
            r = requests.get(self.health_check_url, timeout=10, verify=False)
            if r.status_code == 200:
                data = r.json()
                return 'authorization_endpoint' in data
        except Exception:
            pass
        return False

    def import_config(self, config_file: str = None) -> bool:
        return True

    # ── Compose file generation ─────────────────────────────────────

    def _generate_compose_file(self) -> None:
        work_dir = self.work_dir
        image = self.image
        http_port = self.http_port
        admin_port = self.admin_port
        pg_port = self.pg_port

        compose_content = f"""\
services:
  postgres:
    image: docker.io/library/postgres:17-alpine
    restart: unless-stopped
    env_file:
      - .env
    environment:
      POSTGRES_USER: logto
      POSTGRES_PASSWORD: ${{PG_PASS}}
      POSTGRES_DB: logto
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d logto -U logto"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 10s
    ports:
      - "{pg_port}:5432"
    volumes:
      - {work_dir}/database:/var/lib/postgresql/data

  logto:
    image: {image}
    restart: unless-stopped
    entrypoint: []
    command: ["sh", "-c", "npm run cli db seed -- --swe && npm start"]
    env_file:
      - .env
    environment:
      DB_URL: postgresql://logto:${{PG_PASS}}@postgres:5432/logto
      ENDPOINT: http://127.0.0.1:{http_port}
      ADMIN_ENDPOINT: http://127.0.0.1:{admin_port}
      PORT: "{http_port}"
      ADMIN_PORT: "{admin_port}"
      OIDC_COOKIE_KEYS: ${{OIDC_COOKIE_KEYS}}
      TRUST_PROXY_HEADER: "1"
      ADMIN_DISABLE_LOCALHOST: "1"
    ports:
      - "{http_port}:{http_port}"
      - "{admin_port}:{admin_port}"
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - {work_dir}/connectors:/etc/logto/connectors
"""
        with open(self.compose_path, 'w') as f:
            f.write(compose_content)
        print(f"[Logto] Generated docker-compose.yml: {self.compose_path}")

    def _generate_env_file(self) -> None:
        env_content = f"""\
PG_PASS={self.pg_password}
OIDC_COOKIE_KEYS={self.oidc_cookie_keys}
"""
        with open(self.env_path, 'w') as f:
            f.write(env_content)
        print(f"[Logto] Generated .env file: {self.env_path}")

    # ── Health checking ─────────────────────────────────────────────

    def _wait_for_logto(self, timeout: int) -> bool:
        print(f"[Logto] Waiting for health (timeout: {timeout}s)...")
        start = time.time()
        while time.time() - start < timeout:
            try:
                r = requests.get(self.health_check_url, timeout=10, verify=False)
                if r.status_code == 200:
                    data = r.json()
                    if 'authorization_endpoint' in data:
                        print(f"[Logto] Discovery OK: issuer={data.get('issuer', 'N/A')}")
                        return True
            except Exception:
                pass
            elapsed = int(time.time() - start)
            if elapsed > 0 and elapsed % 15 == 0:
                print(f"[Logto] Still waiting ({elapsed}s)...")
            time.sleep(3)
        return False

    def _print_compose_logs(self):
        try:
            subprocess.run(
                ['docker', 'compose', '-f', self.compose_path, 'logs', '--tail', '80'],
                check=False)
        except Exception:
            pass

    # ── Container management ────────────────────────────────────────

    def _cleanup_containers(self):
        if os.path.exists(self.compose_path):
            subprocess.run(
                ['docker', 'compose', '-f', self.compose_path, 'down', '-v'],
                capture_output=True, text=True, timeout=60)
        # Clean up database files (may have root ownership from postgres container)
        db_dir = os.path.join(self.work_dir, 'database')
        if os.path.exists(db_dir):
            subprocess.run(
                ['docker', 'run', '--rm', '-v', f'{self.work_dir}:/work',
                 'alpine', 'rm', '-rf', '/work/database'],
                capture_output=True, text=True, timeout=15)

    # ── API-based configuration ─────────────────────────────────────

    def _configure_via_api(self) -> bool:
        """Create OIDC application and test user directly via PostgreSQL.

        The Logto Management API (port 3002) may not be fully accessible in
        this image, so we insert the required records straight into the
        database.
        """
        print("[Logto] Configuring via database...")
        oauth_cfg = self.config.get('oauth', {})

        client_id = oauth_cfg.get('client_id', 'fuzz-client')
        client_secret = oauth_cfg.get('client_secret', 'fuzz-client-secret-xK9mP2nQ')
        redirect_uri = oauth_cfg.get('redirect_uri', 'http://127.0.0.1:7777/callback')
        user_name = oauth_cfg.get('user', 'fuzzuser@example.com')
        user_password = oauth_cfg.get('password', 'FuzzPass2025!')
        pg_pass = self.pg_password

        try:
            # --- create OIDC application ---
            print("  [1/3] Creating OIDC application...")
            app_sql = f"""
            INSERT INTO applications (tenant_id, id, name, secret, description, type,
                                      oidc_client_metadata, custom_client_metadata)
            VALUES ('default', '{client_id}', 'Fuzz Client', '{client_secret}',
                    'Auto-created for OAuth fuzzing', 'Traditional',
                    '{{"redirectUris":["{redirect_uri}"],"postLogoutRedirectUris":["{redirect_uri}"],
                      "grantTypes":["authorization_code","refresh_token","client_credentials"],
                      "tokenEndpointAuthMethod":"client_secret_post"}}'::jsonb,
                    '{{"corsAllowedOrigins":["*"],"idTokenTtl":3600,"refreshTokenTtlInDays":14}}'::jsonb)
            ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, secret=EXCLUDED.secret,
                oidc_client_metadata=EXCLUDED.oidc_client_metadata,
                custom_client_metadata=EXCLUDED.custom_client_metadata;
            """
            self._pg_exec(app_sql)
            print(f"  Application '{client_id}' created/updated.")

            # --- create test user ---
            print("  [2/3] Creating test user...")
            import subprocess as _sp
            hash_result = _sp.run(
                ['docker', 'run', '--rm', 'python:3-alpine', 'sh', '-c',
                 'pip install -q argon2-cffi && python3 -c "'
                 f"from argon2 import PasswordHasher; print(PasswordHasher().hash('{user_password}'))"
                 '"'],
                capture_output=True, text=True, timeout=60)
            pw_hash = hash_result.stdout.strip().split('\n')[-1]
            if not pw_hash.startswith('$argon2'):
                print(f"  Warning: password hash generation failed: {pw_hash[:80]}")
                pw_hash = None

            if pw_hash:
                user_sql = f"""
                INSERT INTO users (tenant_id, id, username, primary_email,
                                   password_encrypted, password_encryption_method, name)
                VALUES ('default', 'fuzz-user', '{user_name}', '{user_name}',
                        '{pw_hash}', 'Argon2id', 'Fuzz Test User')
                ON CONFLICT (id) DO UPDATE SET username=EXCLUDED.username,
                    primary_email=EXCLUDED.primary_email,
                    password_encrypted=EXCLUDED.password_encrypted,
                    password_encryption_method=EXCLUDED.password_encryption_method,
                    name=EXCLUDED.name;
                """
                self._pg_exec(user_sql)
                print(f"  User '{user_name}' created/updated.")
            else:
                print("  Skipping user creation (no hash).")

            # --- verify discovery ---
            print("  [3/3] Verifying OIDC discovery...")
            r = requests.get(self.discovery_endpoint, timeout=10, verify=False)
            if r.status_code == 200:
                data = r.json()
                if 'authorization_endpoint' in data:
                    print(f"  Discovery OK: {len(data)} keys, issuer={data.get('issuer', 'N/A')}")
                    return True
            print(f"  Discovery verification returned {r.status_code}")
        except Exception as e:
            print(f"  Database configuration error: {e}")
            import traceback
            traceback.print_exc()

        return True  # Don't block fuzzing on config issues

    def _pg_exec(self, sql: str) -> None:
        """Execute a SQL statement against the Logto PostgreSQL database."""
        import subprocess as _sp
        pg_pass = self.pg_password
        _sp.run(
            ['docker', 'run', '--rm', '--network', 'host',
             '-e', f'PGPASSWORD={pg_pass}',
             'postgres:17-alpine', 'psql',
             '-h', '127.0.0.1', '-p', str(self.pg_port),
             '-U', 'logto', '-d', 'logto', '-c', sql],
            capture_output=True, text=True, timeout=15, check=True)

    # ── Log fetching ────────────────────────────────────────────────

    def get_recent_logs(self, tail: int = 100, keywords: List[str] = None) -> str:
        try:
            if not os.path.exists(self.compose_path):
                return ''
            logs = subprocess.run(
                ['docker', 'compose', '-f', self.compose_path, 'logs', '--tail', str(tail)],
                capture_output=True, text=True, timeout=15)
            output = logs.stdout + logs.stderr
            if keywords:
                lines = output.splitlines()
                output = '\n'.join(
                    l for l in lines
                    if any(kw.lower() in l.lower() for kw in keywords))
            return output
        except Exception:
            return ''
