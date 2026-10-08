#!/usr/bin/env python3
"""
Casdoor Manager for OAuth Fuzzing Framework.
Manages Casdoor (Go-based IAM) Docker lifecycle and operations.

Casdoor is a Go-based identity management platform supporting OAuth2/OIDC.
Uses Beego web framework, XORM ORM, and Casbin authorization.

Go coverage collection follows the same pattern as Authelia:
  1. Build Casdoor with: go build -cover -o casdoor .
  2. Run with GOCOVERDIR=/tmp/coverage
  3. Copy coverage profiles from container
  4. Parse with go tool covdata percent
"""

import subprocess
import time
import requests
import json
import os
import shutil
from typing import Dict, Optional, List

from targets_manager.base import TargetManager
from core.paths import PROJECT_ROOT


class CasdoorManager(TargetManager):
    """
    Casdoor server manager for OAuth fuzzing.

    Casdoor is a Go-based OIDC provider. Coverage collection requires
    Go's built-in coverage instrumentation (not JaCoCo).
    """

    def __init__(self, config: Dict):
        super().__init__(config)  # base init: _atexit_registered etc.
        self.config = config

        casdoor_cfg = config.get('casdoor', {})
        oauth_cfg = config.get('oauth', {})

        self.base_url = oauth_cfg.get('base_url', 'http://127.0.0.1:8000')
        self.container_name = casdoor_cfg.get('container_name', 'casdoor-fuzz')
        self.image = casdoor_cfg.get('image', 'casbin/casdoor:latest')
        self.mysql_container_name = casdoor_cfg.get('mysql_container_name', 'casdoor-mysql')

        # Configuration directories
        self.config_dir = os.path.abspath(casdoor_cfg.get('config_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'casdoor_service', 'config')))
        self.work_dir = os.path.abspath(casdoor_cfg.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'casdoor_service', 'work')))

        # Health check endpoint
        self.health_check_url = casdoor_cfg.get(
            'health_check_url',
            f'{self.base_url}/api/health'
        )

        # Ports
        self.http_port = casdoor_cfg.get('http_port', 8000)

        # Coverage support (Go-based)
        self.coverage_enabled = casdoor_cfg.get('coverage_enabled', False)
        self.coverage_dir = os.path.abspath(casdoor_cfg.get('coverage_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'casdoor_service', 'coverage')))

        # Initialize Go coverage manager
        try:
            from targets_manager.go_coverage_manager import GoCoverageManager, CasdoorErrorPatterns
            self.go_coverage = GoCoverageManager(
                work_dir=self.coverage_dir,
                container_name=self.container_name,
                authelia_base_url=self.base_url
            )
            # Replace error patterns with Casdoor-specific ones
            self.go_coverage.error_patterns = CasdoorErrorPatterns()
            # Override endpoint weights for Casdoor
            self.go_coverage._oauth_endpoint_weights = {
                'authorization': 1.5,
                'token': 2.0,
                'userinfo': 1.5,
                'introspection': 1.8,
                'auto_signin': 2.5,       # C9 MEDIUM — passwords in GET
                'get_account': 2.0,        # Session cookie inspection
                'cors_preflight': 1.5,     # C17 INFO — CORS origin echo
                'jwks': 1.0,
                'discovery': 0.8,
            }
            if self.coverage_enabled:
                print(f"[GoCoverage] Enabled for Casdoor (hybrid mode)")
            else:
                print(f"[GoCoverage] State-based tracking enabled for Casdoor")
        except ImportError as e:
            print(f"[GoCoverage] go_coverage_manager.py not found: {e}")
            self.go_coverage = None

        self.jacoco = None

    def start(self) -> bool:
        return self.start_casdoor()

    def stop(self) -> None:
        self.stop_casdoor()

    def start_casdoor(self) -> bool:
        """Start Casdoor container with proper configuration."""
        print("=" * 60)
        print("Starting Casdoor (Go-based OAuth/OIDC provider)...")
        print("=" * 60)

        # Try to reuse stopped Casdoor + MySQL containers
        reuse = self._try_reuse_stopped(health_timeout=60)
        if reuse is True:
            print("Casdoor reused existing containers")
            return True
        if reuse is False:
            # Container exists but unhealthy — remove and redeploy
            print("  Existing Casdoor container unhealthy, redeploying...")
            self._remove_container(self.container_name)
            self._remove_container(self.mysql_container_name)

        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)

        # Casdoor uses a conf/app.conf file for configuration
        if not self._generate_configuration():
            print("Failed to generate Casdoor configuration")
            return False

        if not self._ensure_db_sidecar():
            print("Failed to start postgres sidecar")
            return False

        cmd = self._build_docker_command()

        try:
            print(f"Starting container: {' '.join(cmd[:10])}...")
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            container_id = result.stdout.strip()
            print(f"Casdoor container started: {container_id}")

            if not self._wait_for_casdoor():
                print("Casdoor failed to start properly")
                self._print_container_logs(tail=100)
                return False

            print("Casdoor is ready for fuzzing!")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to start Casdoor: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                print(f"STDERR: {e.stderr}")
            return False

    def stop_casdoor(self) -> None:
        """Stop (but do not remove) Casdoor and MySQL containers for reuse."""
        print("Stopping Casdoor...")
        self._stop_container(self.container_name)
        self._stop_container(self.mysql_container_name)
        print("Casdoor stopped (containers preserved for reuse)")

    def is_healthy(self) -> bool:
        """Check if Casdoor is healthy."""
        try:
            resp = requests.get(self.health_check_url, timeout=5)
            if resp.status_code == 200:
                return True
            return False
        except requests.exceptions.RequestException:
            return False

    def import_config(self, config_file: str = None) -> bool:
        """Casdoor uses file-based conf/app.conf and init_data.json."""
        print("Casdoor configuration imported via conf files")
        return True

    def _remove_container(self, name: str) -> None:
        """Force-remove a container (only used when unhealthy)."""
        try:
            subprocess.run(
                ['docker', 'rm', '-f', name],
                capture_output=True, text=True, timeout=30
            )
        except Exception:
            pass

    DB_NET = 'casdoor-fuzz-net'
    DB_CONTAINER = 'casdoor-db'

    def _ensure_db_sidecar(self) -> bool:
        """Postgres sidecar on a dedicated network (the stock casdoor binary
        has no sqlite driver; app.conf points at host `casdoor-db`)."""
        import time as _t
        r = subprocess.run(['docker', 'network', 'inspect', self.DB_NET],
                           capture_output=True)
        if r.returncode != 0:
            subprocess.run(['docker', 'network', 'create', self.DB_NET],
                           capture_output=True, check=True)
        running = subprocess.run(
            ['docker', 'ps', '--filter', f'name=^{self.DB_CONTAINER}$',
             '--format', '{{.Names}}'],
            capture_output=True, text=True).stdout.strip()
        if running != self.DB_CONTAINER:
            subprocess.run(['docker', 'rm', '-f', self.DB_CONTAINER],
                           capture_output=True)
            r = subprocess.run(
                ['docker', 'run', '-d', '--name', self.DB_CONTAINER,
                 '--network', self.DB_NET,
                 '-e', 'POSTGRES_USER=casdoor',
                 '-e', 'POSTGRES_PASSWORD=casdoor-fuzz-pw',
                 '-e', 'POSTGRES_DB=casdoor',
                 'postgres:16-alpine'],
                capture_output=True, text=True)
            if r.returncode != 0:
                print(f"sidecar start failed: {r.stderr[-200:]}")
                return False
        for _ in range(30):
            ok = subprocess.run(
                ['docker', 'exec', self.DB_CONTAINER, 'pg_isready',
                 '-U', 'casdoor', '-d', 'casdoor'],
                capture_output=True)
            if ok.returncode == 0:
                print("postgres sidecar ready")
                return True
            _t.sleep(1)
        print("postgres sidecar never became ready")
        return False

    def _build_docker_command(self) -> List[str]:
        """Build Docker run command for Casdoor."""
        cmd = [
            'docker', 'run', '-d',
            '--name', self.container_name,
            '--network', self.DB_NET,
            '-p', f'{self.http_port}:8000',
            '-v', f'{self.config_dir}:/conf:ro',
            '-e', 'TZ=UTC',
        ]

        # Add Go coverage environment and volumes if enabled
        if self.coverage_enabled and self.go_coverage:
            coverage_env = self.go_coverage.setup_coverage_environment()
            for key, value in coverage_env.items():
                cmd.extend(['-e', f'{key}={value}'])
            coverage_volumes = self.go_coverage.get_docker_volume_mounts()
            cmd.extend(coverage_volumes)

        env_vars = self.config.get('casdoor', {}).get('environment', {})
        for key, value in env_vars.items():
            cmd.extend(['-e', f'{key}={value}'])

        cmd.append(self.image)

        return cmd

    def _wait_for_casdoor(self, timeout: int = 120) -> bool:
        """Wait for Casdoor to be ready."""
        print(f"Waiting for Casdoor to be ready (timeout: {timeout}s)...")

        start = time.time()
        interval = 2

        while time.time() - start < timeout:
            try:
                chk = subprocess.run(
                    ['docker', 'ps', '-q', '--filter', f'name={self.container_name}'],
                    capture_output=True, text=True
                )
                if not chk.stdout.strip():
                    print("\n[ERROR] Container exited unexpectedly!")
                    self._print_container_logs(tail=100)
                    return False
            except Exception:
                pass

            try:
                resp = requests.get(self.health_check_url, timeout=5)
                if resp.status_code == 200:
                    print("\nCasdoor health check passed")
                    return True
            except requests.exceptions.RequestException:
                pass

            elapsed = int(time.time() - start)
            if elapsed % 10 == 0 and elapsed > 0:
                print(f"  Still waiting... ({elapsed}s elapsed)")

            time.sleep(interval)
            interval = min(interval * 1.1, 5)

        return False

    def _print_container_logs(self, tail: int = 50) -> None:
        """Print container logs for debugging."""
        try:
            logs = subprocess.run(
                ['docker', 'logs', '--tail', str(tail), self.container_name],
                capture_output=True, text=True
            )
            print(f"=== Casdoor logs (last {tail} lines) ===")
            print(logs.stdout)
            if logs.stderr:
                print("=== STDERR ===")
                print(logs.stderr)
        except Exception as e:
            print(f"Failed to get logs: {e}")

    def _generate_configuration(self) -> bool:
        """Generate Casdoor configuration (conf/app.conf)."""
        try:
            oauth_cfg = self.config.get('oauth', {})

            conf_content = self._build_app_conf(oauth_cfg)
            conf_path = os.path.join(self.config_dir, 'app.conf')
            with open(conf_path, 'w') as f:
                f.write(conf_content)
            print(f"Generated: {conf_path}")
            return True

        except Exception as e:
            print(f"Failed to generate configuration: {e}")
            return False

    def _build_app_conf(self, oauth_cfg: Dict) -> str:
        """Build Casdoor app.conf content."""
        client_id = oauth_cfg.get('client_id', 'fuzz-client')
        client_secret = oauth_cfg.get('client_secret', 'fuzz-client-secret')

        return f"""appname = casdoor
httpport = 8000
runmode = dev
copyrequestbody = true
# the stock casbin/casdoor binary registers only the mysql/postgres drivers
# (driverName=sqlite3 panics: "sql: unknown driver") — postgres sidecar it is
driverName = postgres
dataSourceName = "host=casdoor-db port=5432 user=casdoor password=casdoor-fuzz-pw dbname=casdoor sslmode=disable"
dbName = casdoor
tableNamePrefix =
showSql = false
redisEndpoint =
defaultStorageProvider =
isCloudIntranet = false
authState = "production"
casdoorDbName = "casdoor"
casdoorDbNameIntl = "casdoor"
ldapServerPort = 389
radiusServerPort = 1812
radiusSecret = "secret"
quota = {{"organization": -1, "user": -1, "application": -1, "provider": -1}}
logConfig = ""
enableGzip = true
inactivityTimeoutMinutes = 30
origin =
staticBaseUrl = "https://cdn.casbin.org"
isDemoMode = false
batchSize = 100
enableErrorMask = false
enableGiteeOss = false
enableForum = false
enableLicense = false
secretKey = "casdoor-fuzz-secret-key-32bytes"
likeCountFields = "table1-col1,table1-col2,table2-col1"
initDataFile = "init_data.json"
frontendBaseDir = ""
"""


def main():
    """CLI entry point (mirrors keycloak_manager's dispatch) — required by
    experiments/common.py ensure_up, which provisions targets via
    `python3 -m targets_manager.casdoor_manager --config ... --action start`."""
    import argparse
    import json as _json

    parser = argparse.ArgumentParser(description='Casdoor manager')
    parser.add_argument('--config', default='configs/oauth_casdoor.json')
    parser.add_argument('--action', choices=['start', 'stop', 'restart', 'status'],
                        default='start')
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = _json.load(f)
    cm = CasdoorManager(config)

    if args.action == 'start':
        ok = cm.start_casdoor()
        print('casdoor start:', 'OK' if ok else 'FAILED')
        raise SystemExit(0 if ok else 1)
    elif args.action == 'stop':
        cm.stop_casdoor()
        print('casdoor stopped')
    elif args.action == 'restart':
        cm.stop_casdoor()
        ok = cm.start_casdoor()
        print('casdoor restart:', 'OK' if ok else 'FAILED')
        raise SystemExit(0 if ok else 1)
    else:
        print('healthy:', cm.is_healthy() if hasattr(cm, 'is_healthy') else 'n/a')


if __name__ == '__main__':
    main()
