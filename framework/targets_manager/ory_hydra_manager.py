#!/usr/bin/env python3
"""
Ory Hydra Manager for OAuth Fuzzing Framework.
Manages Ory Hydra (Go-based OAuth2/OIDC provider) Docker lifecycle.

Ory Hydra is a certified OAuth2/OIDC provider that requires an external
identity provider (IDP) for user authentication. For fuzzing, we use
the admin API to accept login/consent requests directly.

Go coverage collection follows the same pattern as Authelia:
  1. Build with: go build -cover -tags sqlite -o hydra .
  2. Run with GOCOVERDIR=/tmp/coverage
  3. Use DSN: sqlite://file::memory:?_fk=true for ephemeral storage
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


class OryHydraManager(TargetManager):
    """
    Ory Hydra server manager for OAuth fuzzing.

    Ory Hydra is a Go-based OAuth2/OIDC provider. Since Hydra delegates
    user authentication to external IDPs, we configure it with a mock
    IDP via the admin API.
    """

    def __init__(self, config: Dict):
        super().__init__(config)  # base init: _atexit_registered etc.
        self.config = config

        hydra_cfg = config.get('ory_hydra', {})
        oauth_cfg = config.get('oauth', {})

        self.base_url = oauth_cfg.get('base_url', 'http://127.0.0.1:4444')
        self.admin_url = hydra_cfg.get('admin_url', 'http://127.0.0.1:4445')
        self.container_name = hydra_cfg.get('container_name', 'ory-hydra-fuzz')
        self.image = hydra_cfg.get('image', 'oryd/hydra:latest')

        # Health check
        self.health_check_url = hydra_cfg.get(
            'health_check_url',
            f'{self.admin_url}/health/ready'
        )
        self.public_health_url = hydra_cfg.get(
            'public_health_url',
            f'{self.base_url}/health/ready'
        )

        # Ports
        self.public_port = hydra_cfg.get('public_port', 4444)
        self.admin_port = hydra_cfg.get('admin_port', 4445)

        # Coverage support (Go-based)
        self.coverage_enabled = hydra_cfg.get('coverage_enabled', False)
        self.coverage_dir = os.path.abspath(hydra_cfg.get('coverage_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'hydra_service', 'coverage')))

        # Initialize Go coverage manager
        try:
            from targets_manager.go_coverage_manager import GoCoverageManager, OryHydraErrorPatterns
            self.go_coverage = GoCoverageManager(
                work_dir=self.coverage_dir,
                container_name=self.container_name,
                authelia_base_url=self.base_url
            )
            self.go_coverage.error_patterns = OryHydraErrorPatterns()
            self.go_coverage._oauth_endpoint_weights = {
                'authorization': 1.5,
                'token': 2.0,
                'userinfo': 1.5,
                'introspection': 1.8,
                'revocation': 1.3,
                'par': 1.5,
                'admin_api': 3.0,          # Admin API is high-value attack surface
                'client_creation': 2.5,     # Dynamic client registration
                'login_accept': 2.0,
                'consent_accept': 2.0,
                'jwks': 1.0,
                'discovery': 0.8,
            }
            if self.coverage_enabled:
                print(f"[GoCoverage] Enabled for Ory Hydra (hybrid mode)")
            else:
                print(f"[GoCoverage] State-based tracking enabled for Ory Hydra")
        except ImportError as e:
            print(f"[GoCoverage] go_coverage_manager.py not found: {e}")
            self.go_coverage = None

        self.jacoco = None

    def start(self) -> bool:
        return self.start_hydra()

    def stop(self) -> None:
        self.stop_hydra()

    def start_hydra(self) -> bool:
        """Start Ory Hydra container."""
        print("=" * 60)
        print("Starting Ory Hydra (Go-based OAuth2/OIDC provider)...")
        print("=" * 60)

        # External-managed mode: the instance (e.g. the cover-instrumented
        # ablation instance on 4474/4475) is provisioned and maintained by an
        # external script; this manager only health-checks and re-provisions.
        if self.config.get('ory_hydra', {}).get('external_managed'):
            if self._external_healthy():
                print(f"[Hydra] external instance healthy ({self.base_url})")
                return True
            script = self.config.get('ory_hydra', {}).get('provision_script')
            if script:
                print(f"[Hydra] re-provisioning via {script}")
                r = subprocess.run(['bash', script], capture_output=True,
                                   text=True, timeout=900)
                if r.returncode == 0 and self._external_healthy():
                    print("[Hydra] external instance re-provisioned")
                    return True
            print("[Hydra] external instance NOT healthy; giving up")
            return False

        # Reuse-first: if a (config-named) container is already running and
        # healthy, skip the destructive redeploy below.
        reuse = self._try_reuse_stopped(health_timeout=60)
        if reuse is True:
            print(f"Ory Hydra reused existing container: {self.container_name}")
            return True
        if reuse is False:
            print("  Existing container unhealthy, redeploying...")
            subprocess.run(['docker', 'rm', '-f', self.container_name],
                           capture_output=True, text=True, timeout=30)

        self._cleanup_container()

        cmd = self._build_docker_command()

        try:
            print(f"Starting container: {' '.join(cmd[:10])}...")
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            container_id = result.stdout.strip()
            print(f"Ory Hydra container started: {container_id}")

            if not self._wait_for_hydra():
                print("Ory Hydra failed to start properly")
                self._print_container_logs(tail=100)
                return False

            # Create test OAuth2 client
            if not self._create_test_client():
                print("Failed to create test OAuth2 client")
                return False

            print("Ory Hydra is ready for fuzzing!")
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to start Ory Hydra: {e}")
            if hasattr(e, 'stderr') and e.stderr:
                print(f"STDERR: {e.stderr}")
            return False

    def stop_hydra(self) -> None:
        """Stop Ory Hydra container."""
        if self.config.get('ory_hydra', {}).get('external_managed'):
            print("[Hydra] external-managed: leaving container running")
            return
        print("Stopping Ory Hydra...")
        try:
            chk = subprocess.run(
                ['docker', 'ps', '-aq', '--filter', f'name={self.container_name}'],
                check=True, capture_output=True, text=True
            )
            cid = (chk.stdout or '').strip()
            if not cid:
                print("Ory Hydra container not running; skip stop.")
                return

            subprocess.run(
                ['docker', 'stop', self.container_name],
                check=True, capture_output=True, text=True
            )
            print("Ory Hydra stopped")
        except subprocess.CalledProcessError as e:
            print(f"Failed to stop Ory Hydra: {e}")

    def _external_healthy(self) -> bool:
        """Health probe for externally-managed instances (discovery or /health/ready)."""
        for url in (f'{self.base_url}/.well-known/openid-configuration',
                    f'{self.admin_url}/health/ready',
                    f'{self.base_url}/health/ready'):
            try:
                if requests.get(url, timeout=5).status_code == 200:
                    return True
            except requests.exceptions.RequestException:
                continue
        return False

    def is_healthy(self) -> bool:
        """Check if Ory Hydra is healthy."""
        try:
            resp = requests.get(self.health_check_url, timeout=5)
            if resp.status_code == 200:
                return True
            # Also check public health
            resp2 = requests.get(self.public_health_url, timeout=5)
            return resp2.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def import_config(self, config_file: str = None) -> bool:
        """Ory Hydra uses CLI flags and environment variables — config is set at start."""
        print("Ory Hydra configuration set via Docker command")
        return True

    def _cleanup_container(self) -> None:
        """Remove existing container."""
        try:
            subprocess.run(
                ['docker', 'rm', '-f', self.container_name],
                capture_output=True, text=True
            )
            print("Cleaned up existing Ory Hydra container")
        except subprocess.CalledProcessError:
            pass

    def _build_docker_command(self) -> List[str]:
        """Build Docker run command for Ory Hydra."""
        hydra_cfg = self.config.get('ory_hydra', {})

        # Generate a random system secret
        import secrets as sec_module
        system_secret = sec_module.token_hex(32)

        cmd = [
            'docker', 'run', '-d',
            '--name', self.container_name,
            '-p', f'{self.public_port}:4444',
            '-p', f'{self.admin_port}:4445',
            '-e', 'TZ=UTC',
            '-e', f'SECRETS_SYSTEM={system_secret}',
            '-e', 'URLS_SELF_ISSUER=http://127.0.0.1:4444/',
            '-e', 'URLS_CONSENT=http://127.0.0.1:3000/consent',
            '-e', 'URLS_LOGIN=http://127.0.0.1:3000/login',
            '-e', 'URLS_LOGOUT=http://127.0.0.1:3000/logout',
            '-e', 'DSN=memory',
            '-e', 'LOG_LEVEL=debug',
            '-e', 'LOG_LEAK_SENSITIVE_VALUES=true',
            '-e', 'TTL_ACCESS_TOKEN=1h',
            '-e', 'TTL_REFRESH_TOKEN=720h',
            '-e', 'TTL_ID_TOKEN=1h',
            '-e', 'TTL_AUTH_CODE=10m',
            '-e', 'OAUTH2_EXPOSE_INTERNAL_ERRORS=true',
            '-e', 'OAUTH2_PKCE_ENFORCED=false',
        ]

        # Add Go coverage
        if self.coverage_enabled and self.go_coverage:
            coverage_env = self.go_coverage.setup_coverage_environment()
            for key, value in coverage_env.items():
                cmd.extend(['-e', f'{key}={value}'])
            coverage_volumes = self.go_coverage.get_docker_volume_mounts()
            cmd.extend(coverage_volumes)

        env_vars = hydra_cfg.get('environment', {})
        for key, value in env_vars.items():
            cmd.extend(['-e', f'{key}={value}'])

        cmd.append(self.image)
        cmd.extend(['serve', 'all', '--dev'])

        return cmd

    def _wait_for_hydra(self, timeout: int = 60) -> bool:
        """Wait for Ory Hydra to be ready."""
        print(f"Waiting for Ory Hydra to be ready (timeout: {timeout}s)...")

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
                    print("\nOry Hydra health check passed")
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
            print(f"=== Ory Hydra logs (last {tail} lines) ===")
            print(logs.stdout)
            if logs.stderr:
                print("=== STDERR ===")
                print(logs.stderr)
        except Exception as e:
            print(f"Failed to get logs: {e}")

    def _create_test_client(self) -> bool:
        """Create a test OAuth2 client via Hydra admin API."""
        oauth_cfg = self.config.get('oauth', {})
        client_id = oauth_cfg.get('client_id', 'fuzz-client')
        client_secret = oauth_cfg.get('client_secret', 'fuzz-client-secret')
        redirect_uri = oauth_cfg.get('redirect_uri', 'http://127.0.0.1:7777/callback')
        scope = oauth_cfg.get('scope', 'openid profile email')

        data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'grant_types': ['authorization_code', 'refresh_token',
                           'client_credentials', 'implicit'],
            'response_types': ['code', 'token', 'id_token'],
            'redirect_uris': [redirect_uri],
            'scope': scope,
            'token_endpoint_auth_method': 'client_secret_basic',
        }
        headers = {'Content-Type': 'application/json'}
        url = f'{self.admin_url}/admin/clients'

        try:
            resp = requests.post(url, json=data, headers=headers, timeout=10)
            if resp.status_code in (200, 201):
                print(f"Created test client: {client_id}")
                return True
            else:
                print(f"Failed to create client: {resp.status_code} {resp.text[:200]}")
                # May already exist
                if resp.status_code == 409:
                    print("Client already exists, continuing...")
                    return True
                return False
        except Exception as e:
            print(f"Error creating test client: {e}")
            return False


def main():
    """CLI entry point (mirrors keycloak_manager's dispatch) — required by
    experiments/common.py ensure_up, which provisions targets via
    `python3 -m targets_manager.ory_hydra_manager --config ... --action start`."""
    import argparse
    import json as _json

    parser = argparse.ArgumentParser(description='ORY Hydra manager')
    parser.add_argument('--config', default='configs/oauth_ory_hydra.json')
    parser.add_argument('--action', choices=['start', 'stop', 'restart', 'status'],
                        default='start')
    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = _json.load(f)
    hm = OryHydraManager(config)

    if args.action == 'start':
        ok = hm.start_hydra()
        print('hydra start:', 'OK' if ok else 'FAILED')
        raise SystemExit(0 if ok else 1)
    elif args.action == 'stop':
        hm.stop_hydra()
        print('hydra stopped')
    elif args.action == 'restart':
        hm.stop_hydra()
        ok = hm.start_hydra()
        print('hydra restart:', 'OK' if ok else 'FAILED')
        raise SystemExit(0 if ok else 1)
    else:
        print('healthy:', hm.is_healthy())


if __name__ == '__main__':
    main()
