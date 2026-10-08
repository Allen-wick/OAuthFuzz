#!/usr/bin/env python3
"""
node-oidc-provider Target Manager

Builds and runs an Express + oidc-provider server for fuzz testing.
Follows the Shiro pattern: docker build from a local server directory,
then docker run with port mapping.

node-oidc-provider exposes:
  - /oidc/auth                     (authorization_code + PKCE)
  - /oidc/token                    (token exchange, refresh, client_credentials)
  - /oidc/me                       (userinfo)
  - /oidc/token/introspection      (introspection)
  - /oidc/token/revocation         (revocation)
  - /oidc/jwks                     (JWKS)
  - /oidc/device/auth              (device authorization)
  - /.well-known/openid-configuration (discovery)
"""

import os
import subprocess
import time
from typing import Dict, List, Optional

import requests

from targets_manager.base import TargetManager
from targets_manager.node_coverage_manager import NodeCoverageManager, NodeOIDCErrorPatterns

from core.paths import PROJECT_ROOT

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
NODEOIDC_SERVER_DIR = os.path.join(PROJECT_ROOT, 'targets_manager', 'nodeoidc_service', 'server')


class NodeOIDCManager(TargetManager):
    """node-oidc-provider target manager."""

    def __init__(self, config: Dict):
        super().__init__(config)
        nodeoidc_cfg = config.get('nodeoidc', {})
        oauth_cfg = config.get('oauth', {})

        self.base_url = oauth_cfg.get('base_url', 'http://127.0.0.1:3000/oidc')
        self.container_name = nodeoidc_cfg.get('container_name', 'node-oidc-fuzz')
        self.image = nodeoidc_cfg.get('image', 'node-oidc-fuzz:latest')
        self.http_port = nodeoidc_cfg.get('http_port', 3000)
        self.server_dir = nodeoidc_cfg.get('server_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'nodeoidc_service', 'server'))
        self.startup_timeout = nodeoidc_cfg.get('startup_timeout', 60)

        self.work_dir = os.path.abspath(nodeoidc_cfg.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'nodeoidc_service', 'work')))
        os.makedirs(self.work_dir, exist_ok=True)

        # Endpoints (relative to base_url which includes /oidc)
        base_plain = f"http://127.0.0.1:{self.http_port}"
        self.auth_endpoint = f"{self.base_url}/auth"
        self.token_endpoint = f"{self.base_url}/token"
        self.userinfo_endpoint = f"{self.base_url}/me"
        self.introspect_endpoint = f"{self.base_url}/token/introspection"
        self.revoke_endpoint = f"{self.base_url}/token/revocation"
        self.jwks_endpoint = f"{self.base_url}/jwks"
        self.discovery_endpoint = f"{self.base_url}/.well-known/openid-configuration"
        self.health_check_url = f"{base_plain}/health"

        # State-based coverage via NodeCoverageManager (Node.js-specific)
        self.go_coverage = NodeCoverageManager(
            work_dir=os.path.join(self.work_dir, 'coverage'),
            container_name=self.container_name,
            base_url=self.base_url,
        )
        self.go_coverage.error_patterns = NodeOIDCErrorPatterns

    # ── Lifecycle ───────────────────────────────────────────────

    def start(self) -> bool:
        print("=" * 70)
        print("Starting node-oidc-provider Server")
        print(f"Server dir: {NODEOIDC_SERVER_DIR}")
        print("=" * 70)

        reuse = self._try_reuse_stopped(health_timeout=30)
        if reuse is True:
            print(f"[NodeOIDC] Reused existing container: {self.container_name}")
            return True
        if reuse is False:
            print(f"  Existing container unhealthy, redeploying...")
            self._remove_container()

        os.makedirs(self.work_dir, exist_ok=True)

        if not self._ensure_image():
            return False
        if not self._start_container():
            return False
        if not self._wait_ready():
            self._print_logs()
            return False
        print(f"[NodeOIDC] Ready at {self.base_url}")
        return True

    def stop(self) -> None:
        print("[NodeOIDC] Stopping...")
        self._stop_container()

    def is_healthy(self) -> bool:
        try:
            r = requests.get(self.health_check_url, timeout=5, verify=False)
            return r.status_code == 200
        except Exception:
            return False

    # ── Docker helpers ──────────────────────────────────────────

    def _container_running(self) -> bool:
        r = subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Running}}', self.container_name],
            capture_output=True, text=True)
        return r.returncode == 0 and r.stdout.strip() == 'true'

    def _remove_container(self):
        subprocess.run(
            ['docker', 'rm', '-f', self.container_name],
            capture_output=True, timeout=30)

    def _stop_container(self):
        subprocess.run(
            ['docker', 'stop', '-t', '5', self.container_name],
            capture_output=True, timeout=15)
        subprocess.run(
            ['docker', 'rm', '-f', self.container_name],
            capture_output=True, timeout=15)

    def _print_logs(self):
        try:
            subprocess.run(
                ['docker', 'logs', '--tail', '100', self.container_name],
                check=False)
        except Exception:
            pass

    def _try_reuse_stopped(self, health_timeout: float = 30):
        """Try to start an existing stopped container.

        Returns True if reused, False if exists but unhealthy, None if no container.
        """
        r = subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Status}}', self.container_name],
            capture_output=True, text=True)
        if r.returncode != 0:
            return None

        status = r.stdout.strip()
        if status == 'running':
            if self.is_healthy():
                return True
            return False

        if status in ('exited', 'stopped', 'created'):
            print(f"[NodeOIDC] Starting existing container...")
            subprocess.run(
                ['docker', 'start', self.container_name],
                capture_output=True, text=True, timeout=30)
            deadline = time.time() + health_timeout
            while time.time() < deadline:
                if self.is_healthy():
                    return True
                time.sleep(2)
            return False

        return None

    def _ensure_image(self) -> bool:
        """Build the Docker image from nodeoidc_server/."""
        server_dir = os.path.join(PROJECT_ROOT, self.server_dir)
        if not os.path.isdir(server_dir):
            print(f"[NodeOIDC] Server directory not found: {server_dir}")
            return False

        nodeoidc_cfg = self.config.get('nodeoidc', {})
        reuse_image = bool(nodeoidc_cfg.get('reuse_image', False))
        if reuse_image:
            chk = subprocess.run(['docker', 'image', 'inspect', self.image],
                                 capture_output=True)
            if chk.returncode == 0:
                print(f"[NodeOIDC] reuse_image=true; skipping rebuild of {self.image}")
                return True

        print(f"[NodeOIDC] Building Docker image: {self.image}")
        r = subprocess.run(
            ['docker', 'build', '-t', self.image, '.'],
            cwd=server_dir, capture_output=False, timeout=600)
        if r.returncode != 0:
            print("[NodeOIDC] Docker build failed")
            return False
        return True

    def _start_container(self) -> bool:
        """Start the node-oidc-provider container."""
        cmd = [
            'docker', 'run', '-d',
            '--name', self.container_name,
            '-p', f'{self.http_port}:3000',
            '-e', f'OIDC_PORT=3000',
            '-e', f'OIDC_ISSUER=http://127.0.0.1:{self.http_port}/oidc',
        ]

        # Pass through client config as env vars
        oauth_cfg = self.config.get('oauth', {})
        client_id = oauth_cfg.get('client_id', 'fuzz-client')
        client_secret = oauth_cfg.get('client_secret', 'fuzz-secret-change-me')
        redirect_uri = oauth_cfg.get('redirect_uri', f'http://127.0.0.1:{self.http_port}/callback')
        cmd.extend([
            '-e', f'CLIENT_ID={client_id}',
            '-e', f'CLIENT_SECRET={client_secret}',
            '-e', f'REDIRECT_URI={redirect_uri}',
        ])

        cmd.append(self.image)

        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            print(f"[NodeOIDC] Container start failed: {r.stderr}")
            return False
        print(f"[NodeOIDC] Container started: {self.container_name}")
        return True

    def _wait_ready(self) -> bool:
        """Wait for the OIDC discovery endpoint to respond."""
        start = time.time()
        while time.time() - start < self.startup_timeout:
            try:
                r = requests.get(self.discovery_endpoint, timeout=5, verify=False)
                if r.status_code == 200:
                    try:
                        data = r.json()
                        if 'authorization_endpoint' in data:
                            print(f"[NodeOIDC] Discovery OK: {data.get('issuer', 'N/A')}")
                            return True
                    except Exception:
                        pass
            except Exception:
                pass
            elapsed = int(time.time() - start)
            if elapsed and elapsed % 10 == 0:
                print(f"[NodeOIDC] Waiting for startup ({elapsed}s) ...")
            time.sleep(2)
        return False

    def get_recent_logs(self, tail: int = 100, keywords: List[str] = None) -> str:
        """Fetch recent container logs."""
        try:
            r = subprocess.run(
                ['docker', 'logs', '--tail', str(tail), self.container_name],
                capture_output=True, text=True, timeout=10)
            logs = r.stdout + r.stderr
            if keywords:
                lines = logs.splitlines()
                logs = '\n'.join(
                    l for l in lines
                    if any(kw.lower() in l.lower() for kw in keywords)
                )
            return logs
        except Exception:
            return ''
