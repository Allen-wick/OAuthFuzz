#!/usr/bin/env python3
"""
Abstract base class for target service managers.
Each OAuth target (Keycloak, Authelia, Spring AS, CXF, WSO2)
extends this.
"""

import atexit
import subprocess
import time
from abc import ABC, abstractmethod
from typing import Optional, Dict, List


class TargetManager(ABC):
    """
    Abstract target service lifecycle manager.

    Implementations handle Docker container lifecycle, health checks,
    and coverage instrumentation setup for their specific target.

    Cleanup strategy: stop() only stops containers without removing them.
    On next start(), stopped containers are reused via docker start,
    avoiding a full redeploy cycle.
    """

    def __init__(self, config: Dict):
        self.config = config
        self.container_name: str = ""
        self.base_url: str = ""
        self.jacoco = None
        self._atexit_registered = False

    @abstractmethod
    def start(self) -> bool:
        """Start the target service. Returns True on success."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stop the target service."""
        ...

    @abstractmethod
    def is_healthy(self) -> bool:
        """Check if the target service is running and responsive."""
        ...

    def import_config(self, config_file: str = None) -> bool:
        """Import configuration (realm/users/clients). No-op for file-based targets."""
        return True

    def get_base_url(self) -> str:
        """Return the base URL of the running target."""
        return self.base_url

    def get_recent_logs(self, tail: int = 100, keywords: List[str] = None) -> str:
        """Get recent container logs with optional keyword filtering."""
        try:
            result = subprocess.run(
                ['docker', 'logs', '--tail', str(tail), self.container_name],
                capture_output=True, text=True, timeout=10
            )
            logs = result.stdout + result.stderr

            if keywords:
                lines = logs.splitlines()
                lowered = [kw.lower() for kw in keywords]
                hits = [ln for ln in lines if any(kw in ln.lower() for kw in lowered)]
                summary = "\n=== Filtered keyword hits ===\n" + (
                    "\n".join(hits) if hits else "(no keyword hits)"
                )
                return logs + "\n" + summary
            return logs
        except Exception as e:
            return f"Failed to get logs: {e}"

    def restart(self) -> bool:
        """Restart the target service."""
        self.stop()
        time.sleep(2)
        return self.start()

    def is_container_running(self) -> bool:
        """Check if the Docker container is running."""
        try:
            result = subprocess.run(
                ['docker', 'ps', '-q', '--filter', f'name={self.container_name}'],
                capture_output=True, text=True, timeout=5
            )
            return bool(result.stdout.strip())
        except Exception:
            return False

    def register_cleanup(self):
        """Register atexit handler to ensure stop() is called on process exit."""
        if self._atexit_registered:
            return
        self._atexit_registered = True
        atexit.register(self._safe_stop)

    def _safe_stop(self):
        """Stop the target, suppressing all errors (safe for atexit/signal)."""
        try:
            self.stop()
        except Exception:
            pass

    def _container_exists(self) -> bool:
        """Check if a container (running or stopped) exists with self.container_name."""
        try:
            r = subprocess.run(
                ['docker', 'ps', '-aq', '--filter', f'name={self.container_name}'],
                capture_output=True, text=True, timeout=5)
            return bool(r.stdout.strip())
        except Exception:
            return False

    def _try_reuse_stopped(self, health_timeout: int = 60) -> Optional[bool]:
        """
        Try to reuse a stopped container by calling ``docker start``.

        Returns
        -------
        True  — container was stopped, has been started, and is now healthy.
        False — container exists but failed to start or become healthy.
        None  — no container with this name exists; caller should do a full deploy.
        """
        try:
            r = subprocess.run(
                ['docker', 'ps', '-aq', '--filter', f'name={self.container_name}'],
                capture_output=True, text=True, timeout=5)
            if not r.stdout.strip():
                return None  # no container at all

            # Container exists — check if already running
            r2 = subprocess.run(
                ['docker', 'inspect', '-f', '{{.State.Running}}', self.container_name],
                capture_output=True, text=True, timeout=5)
            if r2.returncode == 0 and r2.stdout.strip() == 'true':
                if self.is_healthy():
                    print(f"  [{self.container_name}] already running and healthy")
                    return True
                return False  # running but unhealthy

            # Stopped — try to start it
            print(f"  [{self.container_name}] reusing stopped container...")
            r3 = subprocess.run(
                ['docker', 'start', self.container_name],
                capture_output=True, text=True, timeout=30)
            if r3.returncode != 0:
                print(f"  [{self.container_name}] docker start failed: {r3.stderr.strip()}")
                return False

            # Wait for healthy
            t0 = time.time()
            while time.time() - t0 < health_timeout:
                if self.is_healthy():
                    print(f"  [{self.container_name}] restarted successfully")
                    return True
                time.sleep(2)
            print(f"  [{self.container_name}] started but not healthy within {health_timeout}s")
            return False
        except Exception as e:
            print(f"  [{self.container_name}] reuse check failed: {e}")
            return None

    def _stop_container(self, name: str = None):
        """Stop (but do NOT remove) a Docker container. Safe to call repeatedly."""
        cname = name or self.container_name
        try:
            r = subprocess.run(
                ['docker', 'inspect', '-f', '{{.State.Running}}', cname],
                capture_output=True, text=True, timeout=5)
            if r.returncode != 0 or r.stdout.strip() != 'true':
                return  # not running, nothing to do
            subprocess.run(
                ['docker', 'stop', cname],
                capture_output=True, text=True, timeout=30)
            print(f"  Stopped container: {cname}")
        except Exception:
            pass
