#!/usr/bin/env python3
"""
Zitadel Manager for OAuth Fuzzing Framework.
Manages Zitadel (Go-based IAM) Docker lifecycle and operations.

Zitadel is a comprehensive Go-based identity management platform with
OAuth2/OIDC support, gRPC + REST APIs, and multi-tenancy.

Zitadel's Docker setup uses a custom entrypoint with initialization
steps. For fuzzing, we configure it with a pre-configured instance.

Go coverage collection follows the same pattern as Authelia:
  1. Build with: go build -cover -o zitadel .
  2. Run with GOCOVERDIR=/tmp/coverage
  3. Copy coverage profiles from container
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


class ZitadelManager(TargetManager):
    """
    Zitadel server manager for OAuth fuzzing.

    Zitadel is a Go-based IAM platform (OIDC certified). Uses gRPC + REST
    dual API surface. Docker deployment requires masterkey and initial
    configuration.
    """

    def __init__(self, config: Dict):
        super().__init__(config)  # base init: _atexit_registered etc.
        self.config = config

        zitadel_cfg = config.get('zitadel', {})
        oauth_cfg = config.get('oauth', {})

        self.base_url = oauth_cfg.get('base_url', 'http://127.0.0.1:8080')
        self.container_name = zitadel_cfg.get('container_name', 'zitadel-fuzz')
        self.image = zitadel_cfg.get('image', 'ghcr.io/zitadel/zitadel:latest')

        # Health check (Zitadel serves at /ui/console and /healthz)
        self.health_check_url = zitadel_cfg.get(
            'health_check_url',
            f'{self.base_url}/healthz'
        )

        # Ports
        self.http_port = zitadel_cfg.get('http_port', 8080)

        # Master key for encryption
        self.master_key = zitadel_cfg.get('master_key', 'MasterkeyNeedsToHave32Characters')

        # Coverage support (Go-based)
        self.coverage_enabled = zitadel_cfg.get('coverage_enabled', False)
        self.coverage_dir = os.path.abspath(zitadel_cfg.get('coverage_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'zitadel_service', 'coverage')))

        # Initialize Go coverage manager
        try:
            from targets_manager.go_coverage_manager import GoCoverageManager, ZitadelErrorPatterns
            self.go_coverage = GoCoverageManager(
                work_dir=self.coverage_dir,
                container_name=self.container_name,
                authelia_base_url=self.base_url
            )
            self.go_coverage.error_patterns = ZitadelErrorPatterns()
            self.go_coverage._oauth_endpoint_weights = {
                'authorization': 1.5,
                'token': 2.0,
                'userinfo': 1.5,
                'introspection': 1.8,
                'revocation': 1.3,
                'management_api': 2.5,     # Management API is sensitive
                'admin_api': 3.0,           # Admin API is critical
                'auth_api': 2.5,            # Auth API for user operations
                'system_api': 3.0,          # System API — highest value
                'mfa': 2.0,                 # MFA endpoint attacks
                'org_isolation': 2.5,       # Multi-tenant isolation
                'jwks': 1.0,
                'discovery': 0.8,
            }
            if self.coverage_enabled:
                print(f"[GoCoverage] Enabled for Zitadel (hybrid mode)")
            else:
                print(f"[GoCoverage] State-based tracking enabled for Zitadel")
        except ImportError as e:
            print(f"[GoCoverage] go_coverage_manager.py not found: {e}")
            self.go_coverage = None

        self.jacoco = None

    def start(self) -> bool:
        return self.start_zitadel()

    def stop(self) -> None:
        self.stop_zitadel()

    def start_zitadel(self) -> bool:
        """Start Zitadel container."""
        print("=" * 60)
        print("Starting Zitadel (Go-based IAM platform)...")
        print("=" * 60)

        self._cleanup_container()

        cmd = self._build_docker_command()

        try:
            print(f"Starting container: {' '.join(cmd[:10])}...")
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            container_id = result.stdout.strip()
            print(f"Zitadel container started: {container_id}")

            if not self._wait_for_zitadel():
                print("Zitadel failed to start properly")
                self._print_container_logs(tail=100)
                return False

            print("Zitadel is ready for fuzzing!")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to start Zitadel: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                print(f"STDERR: {e.stderr}")
            return False

    def stop_zitadel(self) -> None:
        """Stop Zitadel container."""
        print("Stopping Zitadel...")
        try:
            chk = subprocess.run(
                ['docker', 'ps', '-aq', '--filter', f'name={self.container_name}'],
                check=True, capture_output=True, text=True
            )
            cid = (chk.stdout or '').strip()
            if not cid:
                print("Zitadel container not running; skip stop.")
                return

            subprocess.run(
                ['docker', 'stop', self.container_name],
                check=True, capture_output=True, text=True
            )
            print("Zitadel stopped")
        except subprocess.CalledProcessError as e:
            print(f"Failed to stop Zitadel: {e}")

    def is_healthy(self) -> bool:
        """Check if Zitadel is healthy."""
        try:
            resp = requests.get(self.health_check_url, timeout=5)
            if resp.status_code == 200:
                return True
            return False
        except requests.exceptions.RequestException:
            return False

    def import_config(self, config_file: str = None) -> bool:
        """Zitadel configuration is set via environment variables at startup."""
        print("Zitadel configuration set via Docker environment")
        return True

    def _cleanup_container(self) -> None:
        """Remove existing container."""
        try:
            subprocess.run(
                ['docker', 'rm', '-f', self.container_name],
                capture_output=True, text=True
            )
            print("Cleaned up existing Zitadel container")
        except subprocess.CalledProcessError:
            pass

    def _build_docker_command(self) -> List[str]:
        """Build Docker run command for Zitadel."""
        zitadel_cfg = self.config.get('zitadel', {})

        cmd = [
            'docker', 'run', '-d',
            '--name', self.container_name,
            '-p', f'{self.http_port}:8080',
            '-e', f'ZITADEL_MASTERKEY={self.master_key}',
            '-e', 'ZITADEL_EXTERNALSECURE=false',
            '-e', 'ZITADEL_EXTERNALDOMAIN=127.0.0.1',
            '-e', 'ZITADEL_EXTERNALPORT=8080',
            '-e', 'ZITADEL_TLS_ENABLED=false',
            '-e', 'ZITADEL_DATABASE_POSTGRES_HOST=localhost',
            '-e', 'ZITADEL_DATABASE_POSTGRES_PORT=5432',
            '-e', 'ZITADEL_DATABASE_POSTGRES_DATABASE=zitadel',
            '-e', 'ZITADEL_DATABASE_POSTGRES_USER_USERNAME=zitadel',
            '-e', 'ZITADEL_DATABASE_POSTGRES_USER_PASSWORD=zitadel',
            '-e', 'ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME=zitadel',
            '-e', 'ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD=zitadel',
            '-e', 'ZITADEL_FIRSTINSTANCE_ORG_NAME=FuzzOrg',
            '-e', 'ZITADEL_FIRSTINSTANCE_HUMAN_USERNAME=testuser',
            '-e', 'ZITADEL_FIRSTINSTANCE_HUMAN_PASSWORD=Testpass123!',
            '-e', 'ZITADEL_FIRSTINSTANCE_PATPATH=/machinekey',
            '-e', 'ZITADEL_LOG_LEVEL=debug',
        ]

        # Add Go coverage
        if self.coverage_enabled and self.go_coverage:
            coverage_env = self.go_coverage.setup_coverage_environment()
            for key, value in coverage_env.items():
                cmd.extend(['-e', f'{key}={value}'])
            coverage_volumes = self.go_coverage.get_docker_volume_mounts()
            cmd.extend(coverage_volumes)

        env_vars = zitadel_cfg.get('environment', {})
        for key, value in env_vars.items():
            cmd.extend(['-e', f'{key}={value}'])

        cmd.append(self.image)

        return cmd

    def _wait_for_zitadel(self, timeout: int = 180) -> bool:
        """Wait for Zitadel to be ready. Zitadel initialization can take a while."""
        print(f"Waiting for Zitadel to be ready (timeout: {timeout}s)...")

        start = time.time()
        interval = 3

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
                    print("\nZitadel health check passed")
                    return True
            except requests.exceptions.RequestException:
                pass

            elapsed = int(time.time() - start)
            if elapsed % 15 == 0 and elapsed > 0:
                print(f"  Still waiting... ({elapsed}s elapsed)")

            time.sleep(interval)
            interval = min(interval * 1.1, 10)

        return False

    def _print_container_logs(self, tail: int = 50) -> None:
        """Print container logs for debugging."""
        try:
            logs = subprocess.run(
                ['docker', 'logs', '--tail', str(tail), self.container_name],
                capture_output=True, text=True
            )
            print(f"=== Zitadel logs (last {tail} lines) ===")
            print(logs.stdout)
            if logs.stderr:
                print("=== STDERR ===")
                print(logs.stderr)
        except Exception as e:
            print(f"Failed to get logs: {e}")
