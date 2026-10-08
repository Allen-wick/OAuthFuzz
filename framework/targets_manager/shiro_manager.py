#!/usr/bin/env python3
"""
Apache Shiro OAuth 2.0 Manager

Builds and runs a custom OAuth2 server using Apache Shiro 2.2.0.
The server provides:
  - /oauth2/authorize   (authorization_code + PKCE)
  - /oauth2/token       (token exchange, refresh, client_credentials)
  - /oauth2/userinfo    (user profile)
  - /oauth2/introspect  (token introspection)
  - /oauth2/revoke      (token revocation)
  - /.well-known/openid-configuration (OIDC discovery)
"""

import os
import subprocess
import time
from typing import Dict, List, Optional

import requests

try:
    from core.coverage import JaCoCoManager
except ImportError:
    JaCoCoManager = None

from targets_manager.base import TargetManager

from core.paths import PROJECT_ROOT

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SHIRO_SERVER_DIR = os.path.join(PROJECT_ROOT, 'targets_manager', 'shiro_service', 'server')


class ShiroTargetManager(TargetManager):
    """Apache Shiro OAuth 2.0 target manager."""

    def __init__(self, config: Dict):
        super().__init__(config)  # base init: _atexit_registered etc.
        self.config = config
        shiro_cfg = config.get('shiro', {})
        oauth_cfg = config.get('oauth', {})

        self.base_url = oauth_cfg.get('base_url', 'http://127.0.0.1:8080')
        self.container_name = shiro_cfg.get('container_name', 'shiro-oauth-fuzz')
        self.image = shiro_cfg.get('image', 'oauth2-shiro:latest')
        self.http_port = shiro_cfg.get('http_port', 8080)
        self.config_dir = os.path.abspath(shiro_cfg.get('config_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'shiro_service', 'config')))
        self.work_dir = os.path.abspath(shiro_cfg.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'shiro_service', 'work')))
        self.startup_timeout = shiro_cfg.get('startup_timeout', 180)

        self.auth_endpoint       = f"{self.base_url}/oauth2/authorize"
        self.token_endpoint      = f"{self.base_url}/oauth2/token"
        self.introspect_endpoint = f"{self.base_url}/oauth2/introspect"
        self.revoke_endpoint     = f"{self.base_url}/oauth2/revoke"
        self.userinfo_endpoint   = f"{self.base_url}/oauth2/userinfo"
        self.discovery_endpoint  = f"{self.base_url}/.well-known/openid-configuration"
        self.health_check_url    = f"{self.base_url}/health"

        self.jacoco_enabled = shiro_cfg.get('jacoco_enabled', True)
        self.jacoco = None
        if self.jacoco_enabled and JaCoCoManager:
            jacoco_cfg = config.get('jacoco', {})
            self.jacoco = JaCoCoManager(
                work_dir=jacoco_cfg.get('work_dir', 'jacoco_tools'),
                version=jacoco_cfg.get('version', '0.8.14'))

    def start(self) -> bool:
        print("=" * 70)
        print("Starting Apache Shiro OAuth 2.0 Server")
        print(f"Server dir: {SHIRO_SERVER_DIR}")
        print("=" * 70)

        # Try to reuse a stopped container first
        reuse = self._try_reuse_stopped(health_timeout=60)
        if reuse is True:
            print(f"[Shiro] Reused existing container: {self.container_name}")
            if self.jacoco:
                self._prepare_classpaths()
            return True
        if reuse is False:
            print(f"  Existing container unhealthy, redeploying...")
            self._remove_container()

        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)

        if not self._ensure_image():
            return False
        if not self._start_container():
            return False
        if not self._wait_ready():
            self._print_logs()
            return False
        if self.jacoco:
            self._prepare_classpaths()
        print(f"[Shiro] Ready at {self.base_url}")
        return True

    def stop(self) -> None:
        if self.jacoco and self._container_running():
            try:
                jp = self.config.get('jacoco', {}).get('agent_port', 6300)
                if self._agent_reachable(port=jp):
                    self.jacoco.dump_coverage(port=jp)
            except Exception:
                pass
        print("[Shiro] Stopping...")
        self._stop_container()

    def is_healthy(self) -> bool:
        for url, accept in (
            (self.health_check_url, (200,)),
            (self.auth_endpoint, (302, 400, 401)),
        ):
            try:
                r = requests.get(url, timeout=5, allow_redirects=False, verify=False)
                if r.status_code in accept:
                    return True
            except Exception:
                continue
        return False

    def _agent_reachable(self, port: int, timeout: float = 1.0) -> bool:
        import socket
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=timeout):
                return True
        except Exception:
            return False

    def _container_running(self) -> bool:
        r = subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Running}}', self.container_name],
            capture_output=True, text=True)
        return r.returncode == 0 and r.stdout.strip() == 'true'

    def _remove_container(self):
        """Force-remove container (only used when unhealthy)."""
        subprocess.run(
            ['docker', 'rm', '-f', self.container_name],
            capture_output=True, timeout=30)

    def _print_logs(self):
        try:
            subprocess.run(
                ['docker', 'logs', '--tail', '100', self.container_name],
                check=False)
        except Exception:
            pass

    def _ensure_image(self) -> bool:
        """Build the Docker image from shiro_server/."""
        if not os.path.isdir(SHIRO_SERVER_DIR):
            print(f"[Shiro] Server directory not found: {SHIRO_SERVER_DIR}")
            return False

        # Check if image already exists and reuse_image is set
        shiro_cfg = self.config.get('shiro', {})
        reuse_image = bool(shiro_cfg.get('reuse_image', False))
        if reuse_image:
            chk = subprocess.run(['docker', 'image', 'inspect', self.image],
                                 capture_output=True)
            if chk.returncode == 0:
                print(f"[Shiro] reuse_image=true; skipping rebuild of {self.image}")
                return True

        print(f"[Shiro] Building Docker image: {self.image}")
        r = subprocess.run(
            ['docker', 'build', '-t', self.image, '.'],
            cwd=SHIRO_SERVER_DIR, capture_output=False, timeout=600)
        if r.returncode != 0:
            print("[Shiro] Docker build failed")
            return False
        return True

    def _start_container(self) -> bool:
        """Start the Shiro OAuth container."""
        env_args = []
        if self.jacoco_enabled:
            jp = self.config.get('jacoco', {}).get('agent_port', 6300)
            env_args.extend([
                '-e', f'JACOCO_PORT={jp}'
            ])

        cmd = [
            'docker', 'run', '-d',
            '--name', self.container_name,
            '-p', f'{self.http_port}:8080',
            '-p', '6300:6300',
            '-v', f'{self.config_dir}:/app/config',
            '-v', f'{self.work_dir}:/app/work',
        ] + env_args + [self.image]

        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            print(f"[Shiro] Container start failed: {r.stderr}")
            return False
        print(f"[Shiro] Container started: {self.container_name}")
        return True

    def _wait_ready(self) -> bool:
        start = time.time()
        consecutive_5xx = 0
        while time.time() - start < self.startup_timeout:
            if self.is_healthy():
                return True
            try:
                r = requests.get(self.health_check_url, timeout=5, verify=False)
                status = r.status_code
                if status >= 500:
                    consecutive_5xx += 1
                    if consecutive_5xx >= 3:
                        print(f"[Shiro] Server replied {status} on 3 consecutive probes")
                        self._print_logs()
                        return False
                else:
                    consecutive_5xx = 0
            except Exception:
                pass
            elapsed = int(time.time() - start)
            if elapsed and elapsed % 15 == 0:
                print(f"[Shiro] Waiting for deployment ({elapsed}s) ...")
            time.sleep(3)
        return False

    def _prepare_classpaths(self):
        """Prepare classpath for JaCoCo instrumentation."""
        if not self.jacoco:
            return
        shiro_lib = os.path.join(PROJECT_ROOT, 'jacoco_tools', 'shiro_lib', 'extracted', 'lib')
        if os.path.isdir(shiro_lib):
            print(f"[Shiro] JaCoCo classpath: {shiro_lib}")

    def get_recent_logs(self, tail: int = 100, keywords: List[str] = None) -> str:
        return super().get_recent_logs(tail, keywords)
