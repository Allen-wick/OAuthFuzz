#!/usr/bin/env python3
"""
SimpleLogin Manager for OAuth Fuzzing Framework.
Manages SimpleLogin (Python/Flask alias/email service with OIDC provider)
multi-container Docker Compose lifecycle and operations.

SimpleLogin is a Python/Flask-based email alias service with full OAuth2/OIDC
support. It uses PostgreSQL as its database, deployed via Docker Compose with
separate web and job-runner containers.

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


class SimpleLoginManager(TargetManager):
    """
    SimpleLogin server manager for OAuth fuzzing.

    Manages a multi-container Docker Compose deployment consisting of:
      - PostgreSQL 12 (database)
      - SimpleLogin web (Flask server)
      - SimpleLogin job-runner (background tasks)

    Configuration and user/client provisioning is performed via the
    SimpleLogin registration API and direct psql commands.
    """

    def __init__(self, config: Dict):
        super().__init__(config)

        cfg = config.get('simplelogin', {})
        oauth_cfg = config.get('oauth', {})

        self.base_url = f"http://127.0.0.1:{cfg.get('http_port', 7777)}"
        self.container_name = cfg.get('container_name', 'simplelogin-fuzz')
        self.image = cfg.get('image', 'simplelogin/app-ci:latest')

        # Ports
        self.http_port = cfg.get('http_port', 7777)
        self.db_port = cfg.get('db_port', 54321)

        # Database configuration
        self.db_name = cfg.get('db_name', 'simplelogin')
        self.db_user = cfg.get('db_user', 'sl_user')
        self.db_password = cfg.get('db_password', secrets.token_hex(16))

        # Test user credentials
        self.test_email = oauth_cfg.get('user', 'fuzzuser@test.local')
        self.test_password = oauth_cfg.get('password', 'FuzzTest123!')

        # OAuth client configuration
        self.client_id = oauth_cfg.get('client_id', 'fuzz-client')
        self.client_secret = oauth_cfg.get('client_secret', 'fuzz-client-secret')
        self.redirect_uri = oauth_cfg.get('redirect_uri', 'http://127.0.0.1:7777/callback')

        # Startup timeout in seconds
        self.startup_timeout = cfg.get('startup_timeout', 120)

        # Directories
        self.config_dir = os.path.abspath(cfg.get('config_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'simplelogin_service', 'config')))
        self.work_dir = os.path.abspath(cfg.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'simplelogin_service', 'work')))
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)

        # Compose and env file paths
        self.compose_path = os.path.join(self.config_dir, 'docker-compose.yml')
        self.env_path = os.path.join(self.config_dir, '.env')

        # Generated secrets
        self.flask_secret = secrets.token_hex(32)

        # Initialize Python coverage manager (state-based tracking for Python target)
        try:
            from targets_manager.python_coverage_manager import PythonCoverageManager, SimpleLoginErrorPatterns
            self.go_coverage = PythonCoverageManager(
                work_dir=os.path.join(self.config_dir, 'coverage'),
                container_name=self.container_name,
                base_url=self.base_url
            )
            self.go_coverage.error_patterns = SimpleLoginErrorPatterns
        except ImportError as e:
            print(f"[PythonCoverage] python_coverage_manager.py not found: {e}")
            self.go_coverage = None

        self.jacoco = None

    def start(self) -> bool:
        """Start the full SimpleLogin stack via Docker Compose."""
        print("=" * 60)
        print("Starting SimpleLogin (Python/Flask OIDC provider)...")
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
                capture_output=True, text=True, timeout=600
            )
            if result.returncode != 0:
                print(f"docker compose up failed: {result.stderr}")
                return False
            print("Docker compose services started")

            # Migrations are run inside the web container entrypoint.
            # Just wait for the health check.
            if not self._wait_for_simplelogin(self.startup_timeout):
                print("SimpleLogin failed to become healthy within timeout")
                self._print_compose_logs()
                return False

            if not self._configure_via_db():
                print("Failed to configure SimpleLogin via DB/API")
                return False

            print("SimpleLogin is ready for fuzzing!")
            return True

        except subprocess.TimeoutExpired:
            print("docker compose up timed out")
            return False
        except Exception as e:
            print(f"Failed to start SimpleLogin: {e}")
            return False

    def stop(self) -> None:
        """Stop all SimpleLogin containers and clean up volumes."""
        print("Stopping SimpleLogin...")
        self._cleanup_containers()
        print("SimpleLogin stopped")

    def is_healthy(self) -> bool:
        """Check if SimpleLogin server is healthy."""
        try:
            resp = requests.get(
                f'http://127.0.0.1:{self.http_port}/',
                timeout=5, verify=False
            )
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def import_config(self, config_file: str = None) -> bool:
        """No-op; SimpleLogin configuration is done via DB/API after startup."""
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _generate_compose_file(self) -> None:
        """Write the docker-compose.yml for SimpleLogin."""
        work_dir = self.work_dir
        image = self.image
        http_port = self.http_port
        db_port = self.db_port
        db_dir = os.path.join(work_dir, 'database')
        pgp_dir = os.path.join(work_dir, 'pgp')
        key_dir = os.path.join(work_dir, 'keys')
        for d in (db_dir, pgp_dir, key_dir):
            os.makedirs(d, exist_ok=True)

        compose_content = f"""\
services:
  postgresql:
    image: docker.io/library/postgres:12-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: {self.db_name}
      POSTGRES_PASSWORD: {self.db_password}
      POSTGRES_USER: {self.db_user}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -d {self.db_name} -U {self.db_user}"]
      interval: 10s
      retries: 5
      start_period: 10s
      timeout: 5s
    ports:
      - "{db_port}:5432"
    volumes:
      - {db_dir}:/var/lib/postgresql/data

  web:
    image: {image}
    restart: unless-stopped
    entrypoint: []
    command: sh -c ".venv/bin/alembic upgrade head; python init_app.py; python -c \\"from server import create_app; create_app().run(host='0.0.0.0', port=7777, debug=True, use_reloader=False)\\""
    env_file:
      - .env
    ports:
      - "{http_port}:7777"
    depends_on:
      postgresql:
        condition: service_healthy
    volumes:
      - {pgp_dir}:/sl/pgp
      - {key_dir}:/sl/keys

  job-runner:
    image: {image}
    restart: unless-stopped
    entrypoint: []
    command: sh -c "sleep 30; exec python job_runner.py"
    env_file:
      - .env
    depends_on:
      postgresql:
        condition: service_healthy
    volumes:
      - {pgp_dir}:/sl/pgp
      - {key_dir}:/sl/keys
"""

        with open(self.compose_path, 'w') as f:
            f.write(compose_content)
        print(f"Generated docker-compose.yml: {self.compose_path}")

    def _generate_env_file(self) -> None:
        """Write the .env file consumed by docker-compose.yml."""
        # Generate OIDC RSA key pair inside the work dir
        key_dir = os.path.join(self.work_dir, 'keys')
        os.makedirs(key_dir, exist_ok=True)
        priv_key = os.path.join(key_dir, 'jwtRS256.key')
        pub_key = os.path.join(key_dir, 'jwtRS256.key.pub')
        if not os.path.exists(priv_key):
            subprocess.run(
                ['openssl', 'genrsa', '-out', priv_key, '2048'],
                capture_output=True, timeout=30,
            )
            subprocess.run(
                ['openssl', 'rsa', '-in', priv_key, '-pubout', '-out', pub_key],
                capture_output=True, timeout=30,
            )

        env_content = f"""\
URL=http://127.0.0.1:{self.http_port}
DB_URI=postgresql://{self.db_user}:{self.db_password}@postgresql:5432/{self.db_name}
FLASK_SECRET={self.flask_secret}
EMAIL_DOMAIN=sl.example
FIRST_ALIAS_DOMAIN=sl.example
SUPPORT_EMAIL=admin@sl.example
LOCAL_FILE_UPLOAD=1
DISABLE_ONBOARDING=true
GNUPGHOME=/sl/pgp
NAMESERVERS=1.1.1.1
NOT_SEND_EMAIL=true
MAX_NB_EMAIL_FREE_PLAN=100
EMAIL_SERVERS_WITH_PRIORITY=[(10, "sl.example.")]
OPENID_PRIVATE_KEY_PATH=/sl/keys/jwtRS256.key
OPENID_PUBLIC_KEY_PATH=/sl/keys/jwtRS256.key.pub
WORDS_FILE_PATH=local_data/test_words.txt
ALLOWED_REDIRECT_DOMAINS=[]
PARTNER_API_TOKEN_SECRET=changeme
"""
        with open(self.env_path, 'w') as f:
            f.write(env_content)
        print(f"Generated .env file: {self.env_path}")

    def _wait_for_simplelogin(self, timeout: int) -> bool:
        """Poll the health endpoint and Docker services until ready."""
        print(f"Waiting for SimpleLogin to be ready (timeout: {timeout}s)...")
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
                    services_running = 0
                    for line in ps.stdout.strip().splitlines():
                        try:
                            svc = json.loads(line)
                            health = svc.get('Health', svc.get('Status', ''))
                            state = svc.get('State', '')
                            if state.lower() in ('running',) or 'running' in str(health).lower():
                                services_running += 1
                        except json.JSONDecodeError:
                            if line.strip():
                                services_running += 1
                    if services_running < 2:
                        elapsed = int(time.time() - start)
                        if elapsed > 30:
                            print(f"  Warning: only {services_running}/3 services running ({elapsed}s)")
            except Exception:
                pass

            # Check health endpoint
            try:
                resp = requests.get(
                    f'http://127.0.0.1:{self.http_port}/',
                    timeout=5, verify=False
                )
                if resp.status_code == 200:
                    print(f"\nSimpleLogin health check passed (status {resp.status_code})")
                    return True
            except requests.exceptions.RequestException:
                pass

            elapsed = int(time.time() - start)
            if elapsed % 15 == 0 and elapsed > 0:
                print(f"  Still waiting... ({elapsed}s elapsed)")

            time.sleep(interval)

        return False

    def _run_migrations(self) -> bool:
        """Run database migrations via docker compose exec."""
        print("Running database migrations...")

        # alembic upgrade head (SimpleLogin uses raw alembic, not flask-migrate)
        print("  Running alembic upgrade head...")
        try:
            result = subprocess.run(
                ['docker', 'compose', '-f', self.compose_path, 'exec', 'job-runner',
                 '.venv/bin/alembic', 'upgrade', 'head'],
                capture_output=True, text=True, timeout=120
            )
            # alembic may output SyntaxWarnings to stderr but still succeed
            if result.returncode != 0 and 'Running upgrade' not in result.stderr:
                print(f"    alembic upgrade failed: {result.stderr}")
                return False
            print("    alembic upgrade completed")
        except subprocess.TimeoutExpired:
            print("    alembic upgrade timed out")
            return False
        except Exception as e:
            print(f"    alembic upgrade error: {e}")
            return False

        # python init_app.py
        print("  Running python init_app.py...")
        try:
            result = subprocess.run(
                ['docker', 'compose', '-f', self.compose_path, 'exec', 'web',
                 'python', 'init_app.py'],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode != 0:
                print(f"    init_app.py failed: {result.stderr}")
                return False
            print("    init_app.py completed")
        except subprocess.TimeoutExpired:
            print("    init_app.py timed out")
            return False
        except Exception as e:
            print(f"    init_app.py error: {e}")
            return False

        print("Database migrations completed successfully")
        return True

    def _configure_via_db(self) -> bool:
        """Configure SimpleLogin by creating user and OAuth client directly in PostgreSQL."""
        print("Configuring SimpleLogin via DB...")

        psql_base = ['docker', 'compose', '-f', self.compose_path, 'exec', '-T',
                     'postgresql', 'psql', '-U', self.db_user, '-d', self.db_name]

        # 1. Create user directly in DB (bypasses email validation)
        print("  [1/5] Creating test user in DB...")
        # Generate bcrypt hash via the web container's python
        try:
            hash_result = subprocess.run(
                ['docker', 'compose', '-f', self.compose_path, 'exec', '-T',
                 'web', 'python', '-c',
                 f'import bcrypt; '
                 f'print(bcrypt.hashpw("{self.test_password}".encode(), bcrypt.gensalt()).decode())'],
                capture_output=True, text=True, timeout=15
            )
            password_hash = hash_result.stdout.strip()
            if not password_hash:
                print("    Failed to generate password hash")
                return False
        except Exception as e:
            print(f"    Failed to generate password hash: {e}")
            return False

        alt_id = secrets.token_hex(16)
        sql = (
            f"INSERT INTO users "
            f"(email, name, password, activated, is_admin, alternative_id, "
            f" created_at, updated_at) "
            f"VALUES ('{self.test_email}', 'Fuzz User', '{password_hash}', TRUE, FALSE, "
            f" '{alt_id}', NOW(), NOW()) "
            f"ON CONFLICT (email) DO NOTHING;"
        )
        try:
            result = subprocess.run(
                psql_base + ['-c', sql],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                print(f"    Failed to create user: {result.stderr}")
                return False
            print(f"    Created user: {self.test_email}")
        except Exception as e:
            print(f"    Failed to create user: {e}")
            return False

        # 2. Get user_id
        print("  [2/5] Getting user ID...")
        user_id = None
        try:
            result = subprocess.run(
                psql_base + ['-t', '-A', '-c',
                             f"SELECT id FROM users WHERE email='{self.test_email}'"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0 or not result.stdout.strip():
                print(f"    Failed to get user_id: {result.stderr}")
                return False
            user_id = result.stdout.strip()
            print(f"    User ID: {user_id}")
        except Exception as e:
            print(f"    Failed to get user_id: {e}")
            return False

        # 3. Create OAuth client
        print("  [3/5] Creating OAuth client...")
        client_insert = (
            f"INSERT INTO client (name, oauth_client_id, oauth_client_secret, "
            f"user_id, approved, created_at, updated_at) "
            f"VALUES ('Fuzz App', '{self.client_id}', '{self.client_secret}', "
            f"{user_id}, true, NOW(), NOW()) "
            f"ON CONFLICT (oauth_client_id) DO NOTHING;"
        )
        try:
            result = subprocess.run(
                psql_base + ['-c', client_insert],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                print(f"    Failed to create OAuth client: {result.stderr}")
                return False
            print(f"    Created OAuth client (oauth_client_id={self.client_id})")
        except Exception as e:
            print(f"    Failed to create OAuth client: {e}")
            return False

        # Add redirect_uri for the client
        redirect_insert = (
            f"INSERT INTO redirect_uri (client_id, uri, created_at, updated_at) "
            f"SELECT id, '{self.redirect_uri}', NOW(), NOW() "
            f"FROM client WHERE oauth_client_id='{self.client_id}';"
        )
        try:
            subprocess.run(
                psql_base + ['-c', redirect_insert],
                capture_output=True, text=True, timeout=15
            )
        except Exception:
            pass

        # 4. Create a mailbox for the user (needed for alias creation in authorize)
        print("  [4/5] Creating user mailbox...")
        mailbox_insert = (
            f"INSERT INTO mailbox (user_id, email, verified, created_at, updated_at) "
            f"VALUES ({user_id}, '{self.test_email}', true, NOW(), NOW()) "
            f"ON CONFLICT DO NOTHING;"
        )
        try:
            result = subprocess.run(
                psql_base + ['-c', mailbox_insert],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode != 0:
                print(f"    Warning: mailbox creation failed: {result.stderr}")
            else:
                # Set as default mailbox
                subprocess.run(
                    psql_base + ['-c',
                        f"UPDATE users SET default_mailbox_id = "
                        f"(SELECT id FROM mailbox WHERE user_id={user_id} LIMIT 1) "
                        f"WHERE id={user_id};"],
                    capture_output=True, text=True, timeout=15
                )
                print(f"    Created mailbox: {self.test_email}")
        except Exception as e:
            print(f"    Warning: mailbox creation error: {e}")

        # 5. Pre-approve client for user (auto-authorize without consent page)
        print("  [5/5] Pre-approving OAuth client...")
        client_user_insert = (
            f"INSERT INTO client_user (client_id, user_id, created_at, updated_at) "
            f"SELECT id, {user_id}, NOW(), NOW() "
            f"FROM client WHERE oauth_client_id='{self.client_id}' "
            f"ON CONFLICT DO NOTHING;"
        )
        try:
            subprocess.run(
                psql_base + ['-c', client_user_insert],
                capture_output=True, text=True, timeout=15
            )
            print(f"    Pre-approved client for user")
        except Exception:
            pass

        # Add redirect_uri for the client
        redirect_insert = (
            f"INSERT INTO redirect_uri (client_id, uri, created_at, updated_at) "
            f"SELECT id, '{self.redirect_uri}', NOW(), NOW() "
            f"FROM client WHERE oauth_client_id='{self.client_id}';"
        )
        try:
            subprocess.run(
                psql_base + ['-c', redirect_insert],
                capture_output=True, text=True, timeout=15
            )
        except Exception:
            pass

        print("SimpleLogin configuration complete!")
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
        print("Cleaned up existing SimpleLogin containers")

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
            print(f"=== SimpleLogin compose logs (last {tail} lines) ===")
            print(logs.stdout)
            if logs.stderr:
                print("=== STDERR ===")
                print(logs.stderr)
        except Exception as e:
            print(f"Failed to get compose logs: {e}")
