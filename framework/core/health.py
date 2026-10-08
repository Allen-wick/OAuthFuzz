#!/usr/bin/env python3
"""Server health monitoring with target-specific crash detection."""

import subprocess
import time
import requests
from typing import Dict, List, Optional, Tuple

class ServerHealthMonitor:
    """Enhanced server health monitoring with Authelia/Go-specific crash detection"""
    def __init__(self, container_name: str, target_type: str = 'keycloak'):
        self.container_name = container_name
        self.target_type = target_type
        self.last_check_time = time.time()
        self.crash_count = 0
        self.anomaly_count = 0
        self.response_time_history = []
        self.error_count_history = []
        
        # Target-specific crash patterns
        if target_type == 'authelia':
            self.crash_keywords = [
                'panic:', 'runtime error:', 'fatal error:',
                'goroutine', 'nil pointer dereference',
                'index out of range', 'invalid memory address',
                'deadlock', 'SIGABRT', 'SIGSEGV',
                'signal: killed', 'exit status',
            ]
        else:
            self.crash_keywords = [
                'NullPointerException', 'StackOverflowError', 'OutOfMemoryError',
                'IllegalArgumentException', 'ArrayIndexOutOfBoundsException',
                'BufferOverflowException', 'StringIndexOutOfBoundsException',
                'java.lang.Error', 'SIGSEGV', 'SIGABRT', 'core dumped',
                'Fatal error', 'JVM crash', 'hs_err_pid'
            ]
        
        # NEW: Performance anomaly thresholds
        self.response_time_threshold_ms = 5000  # 5 seconds
        self.error_rate_threshold = 0.8  # 80% error rate

    def check_process_alive(self) -> Tuple[bool, str]:
        """Enhanced container health check with performance monitoring"""
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format', '{{.State.Status}}', self.container_name],
                capture_output=True, text=True, timeout=5
            )
            status = (result.stdout or '').strip().lower()
            if status == 'running':
                # Additional health checks
                health_status = self._check_health_endpoint()
                return health_status
            elif status in ('exited', 'dead'):
                self.crash_count += 1
                return False, f'container_status={status}'
            else:
                return True, f'unknown_status={status}'
        except subprocess.TimeoutExpired:
            return False, 'docker_inspect_timeout'
        except Exception as e:
            return True, f'check_error={str(e)[:100]}'
    
    def _check_health_endpoint(self) -> Tuple[bool, str]:
        """Check target's health endpoint"""
        try:
            import requests
            if self.target_type == 'authelia':
                health_url = 'https://127.0.0.1:9091/api/health'
            else:
                health_url = 'http://127.0.0.1:8080/health'
            
            start_time = time.time()
            resp = requests.get(health_url, timeout=5, verify=False)
            response_time_ms = (time.time() - start_time) * 1000
            
            self.response_time_history.append(response_time_ms)
            if len(self.response_time_history) > 100:
                self.response_time_history.pop(0)
            
            if response_time_ms > self.response_time_threshold_ms:
                self.anomaly_count += 1
                return True, f'slow_response={response_time_ms:.0f}ms'
            
            if resp.status_code != 200:
                return True, f'health_status={resp.status_code}'
            
            return True, ''
        except Exception as e:
            return True, f'health_check_error={str(e)[:50]}'

    def check_oom_killed(self) -> bool:
        """Check if container was OOM killed"""
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format', '{{.State.OOMKilled}}', self.container_name],
                capture_output=True, text=True, timeout=5
            )
            return (result.stdout or '').strip().lower() == 'true'
        except Exception:
            return False

    def get_exit_code(self) -> Optional[int]:
        """Get container exit code"""
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format', '{{.State.ExitCode}}', self.container_name],
                capture_output=True, text=True, timeout=5
            )
            code = (result.stdout or '').strip()
            return int(code) if code.isdigit() else None
        except Exception:
            return None

    def extract_crash_signals(self, logs: str) -> List[str]:
        """Extract crash signals from logs with target-specific patterns"""
        found = []
        for kw in self.crash_keywords:
            if kw.lower() in logs.lower():
                found.append(kw)
        return found
    
    def get_recent_errors(self, tail: int = 100) -> Dict:
        """Get recent error statistics from container logs"""
        try:
            result = subprocess.run(
                ['docker', 'logs', '--tail', str(tail), self.container_name],
                capture_output=True, text=True, timeout=10
            )
            logs = result.stdout + result.stderr
            
            error_count = logs.lower().count('error')
            warning_count = logs.lower().count('warning')
            panic_count = logs.lower().count('panic')
            
            return {
                'error_count': error_count,
                'warning_count': warning_count,
                'panic_count': panic_count,
                'crash_signals': self.extract_crash_signals(logs),
                'logs_sample': logs[-2000:] if len(logs) > 2000 else logs
            }
        except Exception as e:
            return {'error': str(e)}

    def get_performance_stats(self) -> Dict:
        """Get performance statistics"""
        if not self.response_time_history:
            return {}
        
        avg_time = sum(self.response_time_history) / len(self.response_time_history)
        max_time = max(self.response_time_history)
        min_time = min(self.response_time_history)
        
        return {
            'avg_response_time_ms': avg_time,
            'max_response_time_ms': max_time,
            'min_response_time_ms': min_time,
            'anomaly_count': self.anomaly_count,
            'crash_count': self.crash_count
        }