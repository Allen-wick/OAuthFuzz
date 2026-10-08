#!/usr/bin/env python3
"""
Authentik Manager for OAuth Fuzzing Framework.
Manages Authentik (Python/Django OIDC provider) multi-container Docker
Compose lifecycle and operations.

Authentik is a Python/Django-based identity provider with full OAuth2/OIDC
support. It uses PostgreSQL as its database and Redis for caching, deployed
via Docker Compose with separate server and worker containers.

Coverage collection uses GoCoverageManager in state-based tracking mode
to record endpoint coverage and error classification.
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


class AuthentikManager(TargetManager):
    """
    Authentik server manager for OAuth fuzzing.

    Manages a multi-container Docker Compose deployment consisting of:
      - PostgreSQL 16 (database)
      - Redis (cache broker)
      - Authentik server (web + API)
      - Authentik worker (background tasks)

    Configuration and user/client provisioning is performed via the
    Authentik Admin API using bootstrap credentials.
    """

    def __init__(self, config: Dict):
        super().__init__(config)  # base init: _atexit_registered etc.
        self.config = config

        cfg = config.get('authentik', {})
        oauth_cfg = config.get('oauth', {})

        self.base_url = f"http://127.0.0.1:{cfg.get('http_port', 9000)}"
        self.container_name = cfg.get('container_name', 'authentik-fuzz')
        self.image = cfg.get('image', 'ghcr.io/goauthentik/server:2026.5.2')

        # Ports
        self.http_port = cfg.get('http_port', 9000)
        self.https_port = cfg.get('https_port', 9443)
        self.pg_port = cfg.get('pg_port', 5432)
        self.redis_port = cfg.get('redis_port', 6379)

        # Bootstrap credentials
        self.bootstrap_password = cfg.get('bootstrap_password', 'bootstrap-admin-password')
        self.bootstrap_token = cfg.get('bootstrap_token', 'bootstrap-token-for-api')
        self.bootstrap_email = cfg.get('bootstrap_email', 'admin@fuzz.local')

        # Application slug for the OAuth2 application
        self.app_slug = cfg.get('app_slug', 'fuzz-app')

        # Startup timeout in seconds
        self.startup_timeout = cfg.get('startup_timeout', 180)

        # Directories
        self.config_dir = os.path.abspath(cfg.get('config_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'authentik_service', 'config')))
        self.work_dir = os.path.abspath(cfg.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'authentik_service', 'work')))
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)

        # Compose and env file paths
        self.compose_path = os.path.join(self.config_dir, 'docker-compose.yml')
        self.env_path = os.path.join(self.config_dir, '.env')

        # Generated secrets
        self.secret_key = secrets.token_hex(50)
        self.pg_password = secrets.token_hex(16)

        # Initialize Python coverage manager (state-based tracking for Python target)
        try:
            from targets_manager.python_coverage_manager import PythonCoverageManager, AuthentikErrorPatterns
            self.go_coverage = PythonCoverageManager(
                work_dir=os.path.join(self.config_dir, 'coverage'),
                container_name=self.container_name,
                base_url=self.base_url
            )
            self.go_coverage.error_patterns = AuthentikErrorPatterns
        except ImportError as e:
            print(f"[PythonCoverage] python_coverage_manager.py not found: {e}")
            self.go_coverage = None

        self.jacoco = None

    def start(self) -> bool:
        """Start the full Authentik stack via Docker Compose."""
        print("=" * 60)
        print("Starting Authentik (Python/Django OIDC provider)...")
        print("=" * 60)

        try:
            self._cleanup_containers()

            # Remove stale config files to force regeneration
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
                print(f"docker compose up failed: {result.stderr}")
                return False
            print("Docker compose services started")

            if not self._wait_for_authentik(self.startup_timeout):
                print("Authentik failed to become healthy within timeout")
                self._print_compose_logs()
                return False

            if not self._configure_via_api():
                print("Failed to configure Authentik via API")
                return False

            print("Authentik is ready for fuzzing!")
            return True

        except subprocess.TimeoutExpired:
            print("docker compose up timed out")
            return False
        except Exception as e:
            print(f"Failed to start Authentik: {e}")
            return False

    def stop(self) -> None:
        """Stop all Authentik containers and clean up volumes."""
        print("Stopping Authentik...")
        self._cleanup_containers()
        print("Authentik stopped")

    def is_healthy(self) -> bool:
        """Check if Authentik server is healthy."""
        try:
            resp = requests.get(
                f'http://127.0.0.1:{self.http_port}/-/health/live/',
                timeout=5, verify=False
            )
            return resp.status_code in (200, 204)
        except requests.exceptions.RequestException:
            return False

    def import_config(self, config_file: str = None) -> bool:
        """No-op; Authentik configuration is done via API after bootstrap."""
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _generate_compose_file(self) -> None:
        """Write the docker-compose.yml matching the official authentik template."""
        work_dir = self.work_dir
        image = self.image
        http_port = self.http_port
        https_port = self.https_port
        data_dir = os.path.join(work_dir, 'data')
        templates_dir = os.path.join(work_dir, 'custom-templates')
        certs_dir = os.path.join(work_dir, 'certs')
        for d in (data_dir, templates_dir, certs_dir):
            os.makedirs(d, exist_ok=True)

        compose_content = f"""\
services:
  postgresql:
    image: docker.io/library/postgres:16-alpine
    restart: unless-stopped
    env_file:
      - .env
    environment:
      POSTGRES_DB: authentik
      POSTGRES_PASSWORD: ${{PG_PASS}}
      POSTGRES_USER: authentik
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d authentik -U authentik"]
      interval: 30s
      retries: 5
      start_period: 20s
      timeout: 5s
    volumes:
      - {work_dir}/database:/var/lib/postgresql/data

  server:
    image: {image}
    restart: unless-stopped
    command: server
    env_file:
      - .env
    environment:
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${{PG_PASS}}
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_SECRET_KEY: ${{AUTHENTIK_SECRET_KEY}}
      AUTHENTIK_BOOTSTRAP_PASSWORD: ${{BOOTSTRAP_PASSWORD}}
      AUTHENTIK_BOOTSTRAP_TOKEN: ${{BOOTSTRAP_TOKEN}}
      AUTHENTIK_BOOTSTRAP_EMAIL: ${{BOOTSTRAP_EMAIL}}
    ports:
      - "{http_port}:9000"
      - "{https_port}:9443"
    depends_on:
      postgresql:
        condition: service_healthy
    shm_size: 512mb
    volumes:
      - {data_dir}:/data
      - {templates_dir}:/templates

  worker:
    image: {image}
    restart: unless-stopped
    command: worker
    env_file:
      - .env
    environment:
      AUTHENTIK_POSTGRESQL__HOST: postgresql
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: ${{PG_PASS}}
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_SECRET_KEY: ${{AUTHENTIK_SECRET_KEY}}
      AUTHENTIK_BOOTSTRAP_PASSWORD: ${{BOOTSTRAP_PASSWORD}}
      AUTHENTIK_BOOTSTRAP_TOKEN: ${{BOOTSTRAP_TOKEN}}
      AUTHENTIK_BOOTSTRAP_EMAIL: ${{BOOTSTRAP_EMAIL}}
    depends_on:
      postgresql:
        condition: service_healthy
    shm_size: 512mb
    user: root
    volumes:
      - {data_dir}:/data
      - {certs_dir}:/certs
      - {templates_dir}:/templates
"""

        with open(self.compose_path, 'w') as f:
            f.write(compose_content)
        print(f"Generated docker-compose.yml: {self.compose_path}")

    def _generate_env_file(self) -> None:
        """Write the .env file consumed by docker-compose.yml."""
        env_content = f"""\
PG_PASS={self.pg_password}
AUTHENTIK_SECRET_KEY={self.secret_key}
BOOTSTRAP_PASSWORD={self.bootstrap_password}
BOOTSTRAP_TOKEN={self.bootstrap_token}
BOOTSTRAP_EMAIL={self.bootstrap_email}
"""
        with open(self.env_path, 'w') as f:
            f.write(env_content)
        print(f"Generated .env file: {self.env_path}")

    def _wait_for_authentik(self, timeout: int) -> bool:
        """Poll the health endpoint and Docker services until ready."""
        print(f"Waiting for Authentik to be ready (timeout: {timeout}s)...")
        start = time.time()
        interval = 5

        while time.time() - start < timeout:
            # Check that all compose services are still running
            try:
                ps = subprocess.run(
                    ['docker', 'compose', '-f', self.compose_path, 'ps',
                     '--format', 'json'],
                    capture_output=True, text=True, timeout=10
                )
                if ps.returncode == 0 and ps.stdout.strip():
                    # docker compose ps --format json outputs one JSON per line
                    services_running = 0
                    for line in ps.stdout.strip().splitlines():
                        try:
                            svc = json.loads(line)
                            health = svc.get('Health', svc.get('Status', ''))
                            state = svc.get('State', '')
                            if state.lower() in ('running',) or 'running' in str(health).lower():
                                services_running += 1
                        except json.JSONDecodeError:
                            # Count non-empty lines as running services
                            if line.strip():
                                services_running += 1
                    if services_running < 3:
                        elapsed = int(time.time() - start)
                        if elapsed > 30:
                            print(f"  Warning: only {services_running}/3 services running ({elapsed}s)")
            except Exception:
                pass

            # Check health endpoint
            try:
                resp = requests.get(
                    f'http://127.0.0.1:{self.http_port}/-/health/live/',
                    timeout=5, verify=False
                )
                if resp.status_code in (200, 204):
                    print(f"\nAuthentik health check passed (status {resp.status_code})")
                    return True
            except requests.exceptions.RequestException:
                pass

            elapsed = int(time.time() - start)
            if elapsed % 15 == 0 and elapsed > 0:
                print(f"  Still waiting... ({elapsed}s elapsed)")

            time.sleep(interval)

        return False

    def _configure_via_api(self) -> bool:
        """Configure Authentik via Admin API using bootstrap token."""
        print("Configuring Authentik via Admin API...")
        oauth_cfg = self.config.get('oauth', {})
        session = requests.Session()
        headers = {'Authorization': f'Bearer {self.bootstrap_token}'}
        base = self.base_url

        # 1. Get or create authorization flow UUID
        print("  [1/7] Getting flows and property mappings...")
        try:
            resp = session.get(f'{base}/api/v3/flows/instances/', headers=headers, timeout=30)
            if resp.status_code != 200:
                print(f"    Failed to get flows: {resp.status_code} {resp.text[:200]}")
                return False
            flows = resp.json()['results']

            # Use implicit-consent authorization flow (no consent prompt)
            authz_flow = next(
                (f for f in flows if f['slug'] == 'default-provider-authorization-implicit-consent'),
                None
            )
            if not authz_flow:
                # Try explicit consent flow
                authz_flow = next(
                    (f for f in flows if f['slug'] == 'default-provider-authorization-explicit-consent'),
                    None
                )
            if not authz_flow:
                # Try any authorization-designated flow
                authz_flow = next(
                    (f for f in flows if f.get('designation') == 'authorization'),
                    None
                )
            if not authz_flow:
                # Create the implicit consent authorization flow
                print("    No authorization flow found, creating one...")
                create_resp = session.post(
                    f'{base}/api/v3/flows/instances/',
                    headers=headers,
                    json={
                        'name': 'Fuzz Authorization',
                        'title': 'Redirecting to %(app)s',
                        'slug': 'default-provider-authorization-implicit-consent',
                        'designation': 'authorization',
                        'policy_engine_mode': 'any',
                    },
                    timeout=30
                )
                if create_resp.status_code in (200, 201):
                    authz_flow = create_resp.json()
                    print(f"    Created authorization flow: {authz_flow['pk']} (no consent stage)")
                else:
                    print(f"    Failed to create flow: {create_resp.status_code} {create_resp.text[:200]}")
                    return False
            authz_flow_pk = authz_flow['pk']

            # Find invalidation flow (required for OAuth2 provider)
            invalidation_flow = next(
                (f for f in flows if f['slug'] == 'default-provider-invalidation-flow'
                 or f['slug'] == 'default-invalidation-flow'),
                None
            )
            if not invalidation_flow:
                invalidation_flow = next(
                    (f for f in flows if f.get('designation') == 'invalidation'),
                    flows[0]
                )
            invalidation_flow_pk = invalidation_flow['pk']
            print(f"    Authorization flow: {authz_flow_pk} ({authz_flow['slug']})")
            print(f"    Invalidation flow: {invalidation_flow_pk}")
        except Exception as e:
            print(f"    Failed to get flows: {e}")
            return False

        # 2. Get signing key UUID
        print("  [2/7] Getting signing key...")
        signing_key = None
        try:
            resp = session.get(f'{base}/api/v3/crypto/certificatekeypairs/', headers=headers, timeout=30)
            if resp.status_code == 200:
                keys = resp.json()['results']
                if keys:
                    signing_key = keys[0]['pk']
                    print(f"    Signing key: {signing_key}")
                else:
                    print("    No signing keys found, proceeding without explicit key")
            else:
                print(f"    Could not get keys ({resp.status_code}), proceeding without explicit key")
        except Exception as e:
            print(f"    Failed to get signing key: {e}")

        # 2b. Get OAuth2 scope property mapping UUIDs
        print("  [2b/7] Getting OAuth2 scope mappings...")
        scope_mapping_uuids = []
        try:
            resp = session.get(
                f'{base}/api/v3/propertymappings/all/?page_size=100',
                headers=headers, timeout=30
            )
            if resp.status_code == 200:
                for pm in resp.json()['results']:
                    managed = pm.get('managed', '')
                    if managed.startswith('goauthentik.io/providers/oauth2/scope'):
                        scope_mapping_uuids.append(pm['pk'])
                print(f"    Found {len(scope_mapping_uuids)} scope mappings")
            else:
                print(f"    Could not get property mappings ({resp.status_code})")
        except Exception as e:
            print(f"    Failed to get property mappings: {e}")

        # 3. Create test user
        print("  [3/7] Creating test user...")
        try:
            username = oauth_cfg.get('user', 'testuser')
            resp = session.post(
                f'{base}/api/v3/core/users/',
                headers=headers,
                json={
                    'username': username,
                    'name': 'Test User',
                    'email': 'testuser@fuzz.local',
                    'path': 'users',
                },
                timeout=30
            )
            if resp.status_code not in (200, 201):
                print(f"    Failed to create user: {resp.status_code} {resp.text[:200]}")
                return False
            user_pk = resp.json()['pk']
            print(f"    Created user: {username} (pk={user_pk})")
        except Exception as e:
            print(f"    Failed to create user: {e}")
            return False

        # 4. Set user password
        print("  [4/7] Setting user password...")
        try:
            password = oauth_cfg.get('password', 'testpass')
            resp = session.post(
                f'{base}/api/v3/core/users/{user_pk}/set_password/',
                headers=headers,
                json={
                    'password': password,
                    'password_repeat': password,
                },
                timeout=30
            )
            if resp.status_code not in (200, 204):
                print(f"    Failed to set password: {resp.status_code} {resp.text[:200]}")
                return False
            print(f"    Password set for user pk={user_pk}")
        except Exception as e:
            print(f"    Failed to set password: {e}")
            return False

        # 5. Create OAuth2 provider
        print("  [5/7] Creating OAuth2 provider...")
        try:
            client_id = oauth_cfg.get('client_id', 'fuzz-client')
            client_secret = oauth_cfg.get('client_secret', 'fuzz-client-secret')
            redirect_uri = oauth_cfg.get('redirect_uri', 'http://127.0.0.1:7777/callback')

            provider_payload = {
                'name': 'Fuzz OAuth Provider',
                'authorization_flow': authz_flow_pk,
                'invalidation_flow': invalidation_flow_pk,
                'client_id': client_id,
                'client_secret': client_secret,
                'redirect_uris': [{'matching_mode': 'strict', 'url': redirect_uri}],
                'grant_types': ['authorization_code', 'refresh_token', 'client_credentials'],
                'access_code_validity': 'minutes=1',
                'token_validity': 'minutes=5',
            }
            if scope_mapping_uuids:
                provider_payload['property_mappings'] = scope_mapping_uuids
            if signing_key:
                provider_payload['signing_key'] = signing_key

            resp = session.post(
                f'{base}/api/v3/providers/oauth2/',
                headers=headers,
                json=provider_payload,
                timeout=30
            )
            if resp.status_code not in (200, 201):
                print(f"    Failed to create provider: {resp.status_code} {resp.text[:200]}")
                return False
            provider_pk = resp.json()['pk']
            print(f"    Created OAuth2 provider (pk={provider_pk})")
        except Exception as e:
            print(f"    Failed to create OAuth2 provider: {e}")
            return False

        # 6. Create application
        print("  [6/7] Creating application...")
        try:
            resp = session.post(
                f'{base}/api/v3/core/applications/',
                headers=headers,
                json={
                    'name': 'Fuzz Application',
                    'slug': self.app_slug,
                    'provider': provider_pk,
                },
                timeout=30
            )
            if resp.status_code not in (200, 201):
                print(f"    Failed to create application: {resp.status_code} {resp.text[:200]}")
                return False
            print(f"    Created application: {self.app_slug}")
        except Exception as e:
            print(f"    Failed to create application: {e}")
            return False

        print("Authentik configuration complete!")
        return True

    def _cleanup_containers(self) -> None:
        """Stop and remove all compose containers and clean data directories."""
        if os.path.exists(self.compose_path):
            try:
                subprocess.run(
                    ['docker', 'compose', '-f', self.compose_path, 'down', '-v'],
                    capture_output=True, text=True, timeout=30
                )
            except subprocess.TimeoutExpired:
                print("Warning: cleanup timed out")
            except Exception:
                pass
        # Remove stale database files (bind mount survives docker compose down)
        # Docker creates files as root, so use docker to clean them
        db_dir = os.path.join(self.work_dir, 'database')
        if os.path.exists(db_dir):
            try:
                subprocess.run(
                    ['docker', 'run', '--rm', '-v',
                     f'{self.work_dir}:/work', 'alpine',
                     'rm', '-rf', '/work/database'],
                    capture_output=True, text=True, timeout=15
                )
            except Exception:
                pass
        print("Cleaned up existing Authentik containers")

    def _print_compose_logs(self, tail: int = 100) -> None:
        """Print recent logs from all compose services for debugging."""
        if not os.path.exists(self.compose_path):
            return
        try:
            logs = subprocess.run(
                ['docker', 'compose', '-f', self.compose_path, 'logs',
                 '--tail', str(tail)],
                capture_output=True, text=True, timeout=15
            )
            print(f"=== Authentik compose logs (last {tail} lines) ===")
            print(logs.stdout)
            if logs.stderr:
                print("=== STDERR ===")
                print(logs.stderr)
        except Exception as e:
            print(f"Failed to get compose logs: {e}")
