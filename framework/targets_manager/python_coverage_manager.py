#!/usr/bin/env python3
"""
Python Coverage Manager for OAuth Fuzzing Framework
Supports state-based coverage collection for Python OAuth targets
(Authentik/Django, SimpleLogin/Flask).

Since Python web frameworks do not have native application coverage
instrumentation equivalent to Go's -cover flag, this manager relies
entirely on state-based coverage: response diversity, endpoint hits,
error pattern discovery, security-path tracking, and vulnerability
indicator detection.
"""

import os
import re
import json
import time
import hashlib
import subprocess
from collections import Counter
from typing import Dict, List, Optional, Set

import requests
from core.paths import PROJECT_ROOT


# ========== ENDPOINT IMPORTANCE WEIGHTS ==========
ENDPOINT_IMPORTANCE = {
    'token': 2.0, 'TokenExchange': 2.0,
    'authorization': 1.5, 'Authorize': 1.5,
    'introspect': 1.8, 'Introspect': 1.8,
    'revoke': 1.7, 'RevokeToken': 1.7,
    'userinfo': 1.3, 'UserInfo': 1.3,
    'device': 1.5, 'DeviceAuthorization': 1.5,
    'admin': 3.0, 'password': 1.5, 'PasswordGrant': 1.5,
    'consent': 2.0, 'Consent': 2.0,
    'refresh': 1.5, 'RefreshToken': 1.5,
}

# Fixed estimate for the OAuth state space used in coverage calculations.
PYTHON_STATE_SPACE_ESTIMATE = 1000


# ========== AUTHENTIK ERROR PATTERN DATABASE ==========
class AuthentikErrorPatterns:
    """Authentik (Python/Django) error pattern recognition database."""

    # OAuth/OIDC Error Codes (RFC 6749)
    OAUTH_ERRORS = {
        'invalid_request': {'severity': 'MEDIUM', 'category': 'protocol'},
        'unauthorized_client': {'severity': 'HIGH', 'category': 'security'},
        'access_denied': {'severity': 'MEDIUM', 'category': 'access'},
        'unsupported_response_type': {'severity': 'LOW', 'category': 'protocol'},
        'invalid_scope': {'severity': 'MEDIUM', 'category': 'protocol'},
        'server_error': {'severity': 'CRITICAL', 'category': 'server'},
        'invalid_client': {'severity': 'HIGH', 'category': 'security'},
        'invalid_grant': {'severity': 'HIGH', 'category': 'security'},
        'unsupported_grant_type': {'severity': 'LOW', 'category': 'protocol'},
        'interaction_required': {'severity': 'LOW', 'category': 'flow'},
        'login_required': {'severity': 'LOW', 'category': 'flow'},
    }

    # Authentik-specific error messages (Django stack)
    AUTHENTIK_ERRORS = {
        'invalid credentials': {'severity': 'MEDIUM', 'category': 'auth'},
        'no active account': {'severity': 'MEDIUM', 'category': 'auth'},
        'flow not found': {'severity': 'MEDIUM', 'category': 'config'},
        'stage not found': {'severity': 'MEDIUM', 'category': 'config'},
        'invalid redirect_uri': {'severity': 'HIGH', 'category': 'security'},
        'redirect uri mismatch': {'severity': 'HIGH', 'category': 'security'},
        'client not found': {'severity': 'MEDIUM', 'category': 'config'},
        'invalid client': {'severity': 'HIGH', 'category': 'security'},
        'token is invalid': {'severity': 'MEDIUM', 'category': 'token'},
        'token is expired': {'severity': 'LOW', 'category': 'token'},
        'application not found': {'severity': 'MEDIUM', 'category': 'config'},
        'csrf verification failed': {'severity': 'HIGH', 'category': 'security'},
        'csrf failed': {'severity': 'HIGH', 'category': 'security'},
        'forbidden': {'severity': 'HIGH', 'category': 'security'},
        'permission denied': {'severity': 'HIGH', 'category': 'security'},
        'invalid grant': {'severity': 'HIGH', 'category': 'security'},
        'code challenge required': {'severity': 'MEDIUM', 'category': 'security'},
        'not found': {'severity': 'LOW', 'category': 'routing'},
        'method not allowed': {'severity': 'LOW', 'category': 'protocol'},
        'request validation failed': {'severity': 'MEDIUM', 'category': 'protocol'},
        'unknown error': {'severity': 'CRITICAL', 'category': 'server'},
    }

    STATUS_PATTERNS = {
        200: {'meaning': 'success', 'weight': 1.0},
        201: {'meaning': 'created', 'weight': 1.0},
        204: {'meaning': 'no_content', 'weight': 1.0},
        302: {'meaning': 'redirect', 'weight': 1.0},
        303: {'meaning': 'see_other', 'weight': 1.0},
        400: {'meaning': 'bad_request', 'weight': 1.5},
        401: {'meaning': 'unauthorized', 'weight': 2.0},
        403: {'meaning': 'forbidden', 'weight': 2.5},
        404: {'meaning': 'not_found', 'weight': 1.2},
        405: {'meaning': 'method_not_allowed', 'weight': 1.3},
        409: {'meaning': 'conflict', 'weight': 1.5},
        429: {'meaning': 'rate_limited', 'weight': 1.2},
        500: {'meaning': 'server_error', 'weight': 3.0},
        502: {'meaning': 'bad_gateway', 'weight': 2.5},
        503: {'meaning': 'unavailable', 'weight': 2.0},
    }

    CRASH_PATTERNS = [
        r'Traceback \(most recent call last\)',
        r'Django Version:',
        r'Exception Type:',
        r'Exception Value:',
        r'Server Error \(500\)',
        r'DisallowedHost',
        r'SuspiciousOperation',
        r'IntegrityError',
        r'OperationalError',
        r'MemoryError',
        r'RecursionError',
        r'ResponseNeverSent',
        r'BadRequest',
    ]

    @classmethod
    def classify_error(cls, response: Dict) -> Dict:
        """Classify an error response and return error metadata."""
        result = {
            'patterns_matched': [],
            'severity': 'LOW',
            'category': 'unknown',
            'is_security_relevant': False,
            'weight_modifier': 1.0
        }

        status_code = response.get('status_code', 0)
        body = response.get('body', '')
        body_lower = body.lower() if isinstance(body, str) else ''

        # Check status code weight
        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        # Check OAuth error codes
        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        # Check Authentik-specific errors
        for error, meta in cls.AUTHENTIK_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'authentik:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        # Boost weight for security-relevant errors
        if result['is_security_relevant']:
            result['weight_modifier'] *= 2.0

        return result

    @classmethod
    def detect_crash(cls, log_content: str) -> Optional[Dict]:
        """Detect Python/Django crash patterns in container logs."""
        for pattern in cls.CRASH_PATTERNS:
            match = re.search(pattern, log_content, re.IGNORECASE)
            if match:
                return {
                    'type': 'crash',
                    'pattern': pattern,
                    'match': match.group(),
                    'severity': 'CRITICAL'
                }
        return None


# ========== SIMPLELOGIN ERROR PATTERN DATABASE ==========
class SimpleLoginErrorPatterns:
    """SimpleLogin (Python/Flask) error pattern recognition database."""

    OAUTH_ERRORS = {
        'invalid_request': {'severity': 'MEDIUM', 'category': 'protocol'},
        'unauthorized_client': {'severity': 'HIGH', 'category': 'security'},
        'access_denied': {'severity': 'MEDIUM', 'category': 'access'},
        'unsupported_response_type': {'severity': 'LOW', 'category': 'protocol'},
        'invalid_scope': {'severity': 'MEDIUM', 'category': 'protocol'},
        'server_error': {'severity': 'CRITICAL', 'category': 'server'},
        'invalid_client': {'severity': 'HIGH', 'category': 'security'},
        'invalid_grant': {'severity': 'HIGH', 'category': 'security'},
        'unsupported_grant_type': {'severity': 'LOW', 'category': 'protocol'},
    }

    SIMPLELOGIN_ERRORS = {
        'invalid credentials': {'severity': 'MEDIUM', 'category': 'auth'},
        'wrong email or password': {'severity': 'MEDIUM', 'category': 'auth'},
        'email not activated': {'severity': 'MEDIUM', 'category': 'auth'},
        'csrf token': {'severity': 'HIGH', 'category': 'security'},
        'invalid csrf token': {'severity': 'HIGH', 'category': 'security'},
        'client not found': {'severity': 'MEDIUM', 'category': 'config'},
        'redirect url does not match': {'severity': 'HIGH', 'category': 'security'},
        'unauthorized': {'severity': 'HIGH', 'category': 'security'},
        'invalid redirect uri': {'severity': 'HIGH', 'category': 'security'},
        'invalid token': {'severity': 'MEDIUM', 'category': 'token'},
        'token is invalid': {'severity': 'MEDIUM', 'category': 'token'},
        'token expired': {'severity': 'LOW', 'category': 'token'},
        'invalid code': {'severity': 'HIGH', 'category': 'security'},
        'code not found': {'severity': 'HIGH', 'category': 'security'},
        'app not found': {'severity': 'MEDIUM', 'category': 'config'},
        'not a valid email': {'severity': 'LOW', 'category': 'validation'},
        'password too short': {'severity': 'LOW', 'category': 'validation'},
        'email already used': {'severity': 'LOW', 'category': 'validation'},
        'rate limit': {'severity': 'MEDIUM', 'category': 'security'},
        'unknown error': {'severity': 'CRITICAL', 'category': 'server'},
    }

    STATUS_PATTERNS = {
        200: {'meaning': 'success', 'weight': 1.0},
        201: {'meaning': 'created', 'weight': 1.0},
        302: {'meaning': 'redirect', 'weight': 1.0},
        303: {'meaning': 'see_other', 'weight': 1.0},
        400: {'meaning': 'bad_request', 'weight': 1.5},
        401: {'meaning': 'unauthorized', 'weight': 2.0},
        403: {'meaning': 'forbidden', 'weight': 2.5},
        404: {'meaning': 'not_found', 'weight': 1.2},
        405: {'meaning': 'method_not_allowed', 'weight': 1.3},
        409: {'meaning': 'conflict', 'weight': 1.5},
        422: {'meaning': 'unprocessable', 'weight': 1.5},
        429: {'meaning': 'rate_limited', 'weight': 1.2},
        500: {'meaning': 'server_error', 'weight': 3.0},
        502: {'meaning': 'bad_gateway', 'weight': 2.5},
        503: {'meaning': 'unavailable', 'weight': 2.0},
    }

    CRASH_PATTERNS = [
        r'Traceback \(most recent call last\)',
        r'ImportError',
        r'ModuleNotFoundError',
        r'SQLAlchemyError',
        r'InternalServerError',
        r'OperationalError',
        r'IntegrityError',
        r'MemoryError',
        r'RecursionError',
        r'TemplateNotFound',
        r'BadRequestKeyError',
        r'WSGIException',
    ]

    @classmethod
    def classify_error(cls, response: Dict) -> Dict:
        """Classify an error response and return error metadata."""
        result = {
            'patterns_matched': [],
            'severity': 'LOW',
            'category': 'unknown',
            'is_security_relevant': False,
            'weight_modifier': 1.0
        }

        status_code = response.get('status_code', 0)
        body = response.get('body', '')
        body_lower = body.lower() if isinstance(body, str) else ''

        # Check status code weight
        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        # Check OAuth error codes
        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        # Check SimpleLogin-specific errors
        for error, meta in cls.SIMPLELOGIN_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'simplelogin:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        # Boost weight for security-relevant errors
        if result['is_security_relevant']:
            result['weight_modifier'] *= 2.0

        return result

    @classmethod
    def detect_crash(cls, log_content: str) -> Optional[Dict]:
        """Detect Python/Flask crash patterns in container logs."""
        for pattern in cls.CRASH_PATTERNS:
            match = re.search(pattern, log_content, re.IGNORECASE)
            if match:
                return {
                    'type': 'crash',
                    'pattern': pattern,
                    'match': match.group(),
                    'severity': 'CRITICAL'
                }
        return None


# ========== PYTHON COVERAGE MANAGER ==========
class PythonCoverageManager:
    """
    State-based coverage manager for Python OAuth targets
    (Authentik/Django, SimpleLogin/Flask).

    Since Python web frameworks lack native runtime coverage
    instrumentation that can be collected from a running container,
    this manager relies entirely on state-based coverage tracking:
    response diversity, endpoint hits, error pattern discovery,
    security-path coverage, and vulnerability indicator detection.

    The public interface mirrors GoCoverageManager so that the
    fuzzing orchestrator can treat both uniformly.
    """

    def __init__(self, work_dir: str, container_name: str, base_url: str):
        """
        Initialize the Python coverage manager.

        Args:
            work_dir: Working directory for coverage artefacts.
            container_name: Docker container name for the target.
            base_url: Base URL of the running target (e.g. http://localhost:9000).
        """
        self.work_dir = work_dir
        self.container_name = container_name
        self.base_url = base_url

        # Directories
        self.report_dir = os.path.join(work_dir, 'coverage_reports')
        os.makedirs(self.report_dir, exist_ok=True)

        # --- state tracking (mirrors GoCoverageManager) ---
        self.unique_states: Set[str] = set()
        self.endpoint_hits: Dict[str, int] = {}
        self.response_codes: Counter = Counter()
        self.error_patterns_seen: List[str] = []
        self.security_findings: List[Dict] = []
        self.security_paths_covered: Set[str] = set()
        self.vulnerability_indicators: List[Dict] = []

        # Execution counter
        self.execution_count: int = 0

        # Coverage history / snapshots
        self.coverage_history: List[Dict] = []
        self.baseline_coverage: Optional[Dict] = None

        # Peak tracking
        self.max_coverage: float = 0.0

        # Crash tracking
        self.crash_events: List[Dict] = []

        # Error pattern recognizer -- set by the target manager to either
        # AuthentikErrorPatterns or SimpleLoginErrorPatterns.
        self.error_patterns = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Response tracking
    # ------------------------------------------------------------------
    def track_response(self, response, endpoint: str = '') -> Dict:
        """
        Record a fuzzing response and update state-based coverage.

        Args:
            response: A dict with keys ``status_code``, ``body``,
                      ``headers``, ``content_type``, ``response_time``,
                      ``error`` -- or a ``requests.Response`` object.
            endpoint: Free-form endpoint label (e.g. ``token``,
                      ``authorization``).

        Returns:
            Dict with ``is_new_state``, ``classification``, and
            ``weight_modifier``.
        """
        self.execution_count += 1

        # Normalise input -- accept both dict and requests.Response
        if isinstance(response, requests.Response):
            resp_dict = {
                'status_code': response.status_code,
                'body': response.text,
                'headers': dict(response.headers),
                'content_type': response.headers.get('Content-Type', ''),
                'response_time': response.elapsed.total_seconds() * 1000 if hasattr(response, 'elapsed') else 0,
                'error': '',
            }
        elif isinstance(response, dict):
            resp_dict = response
        else:
            resp_dict = {
                'status_code': getattr(response, 'status_code', 0),
                'body': getattr(response, 'text', str(response)),
                'headers': {},
                'content_type': '',
                'response_time': 0,
                'error': '',
            }

        status = resp_dict.get('status_code', 0)
        body = resp_dict.get('body', '')
        content_type = resp_dict.get('content_type', '')
        headers = resp_dict.get('headers', {})

        # --- endpoint tracking ---
        if endpoint:
            self.endpoint_hits[endpoint] = self.endpoint_hits.get(endpoint, 0) + 1

        # --- state fingerprint ---
        body_hash = hashlib.md5(
            (body[:500] if body else '').encode('utf-8', errors='replace')
        ).hexdigest()[:10]
        state_sig = f"{endpoint or 'unknown'}:{status}:{content_type}:{body_hash}"
        is_new_state = state_sig not in self.unique_states
        self.unique_states.add(state_sig)

        # --- response code counter ---
        self.response_codes[status] += 1

        # --- error classification (via pluggable error_patterns) ---
        classification = {
            'patterns_matched': [],
            'severity': 'LOW',
            'category': 'unknown',
            'is_security_relevant': False,
            'weight_modifier': 1.0
        }
        if self.error_patterns is not None:
            classification = self.error_patterns.classify_error(resp_dict)

        # Track matched error patterns
        for pattern in classification.get('patterns_matched', []):
            self.error_patterns_seen.append(pattern)

        # --- security findings ---
        security_path = None
        if classification.get('is_security_relevant'):
            finding = {
                'timestamp': time.time(),
                'endpoint': endpoint,
                'status': status,
                'patterns': classification['patterns_matched'],
                'severity': classification['severity'],
                'response_snippet': body[:200] if body else ''
            }
            self.security_findings.append(finding)
            security_path = f"{endpoint}:{classification['category']}:{classification['severity']}"
            self.security_paths_covered.add(security_path)

        # --- vulnerability indicators ---
        vuln_indicator = self._detect_vulnerability_indicator(resp_dict)
        if vuln_indicator:
            self.vulnerability_indicators.append(vuln_indicator)

        return {
            'is_new_state': is_new_state,
            'classification': classification,
            'weight_modifier': classification.get('weight_modifier', 1.0),
            'security_path_new': security_path
        }

    # ------------------------------------------------------------------
    # Vulnerability indicator detection
    # ------------------------------------------------------------------
    def _detect_vulnerability_indicator(self, response: Dict) -> Optional[Dict]:
        """
        Heuristic detection of potential vulnerability indicators
        in a single response.

        Checks for information disclosure, authentication bypass,
        injection errors, and timing anomalies.
        """
        body = str(response.get('body', ''))
        body_lower = body.lower()
        status = response.get('status_code', 0)
        endpoint = response.get('endpoint', '')

        indicators = []

        # 1. Information disclosure -- stack trace in server error
        if status >= 500 and ('stack' in body_lower or 'trace' in body_lower
                              or 'exception' in body_lower):
            indicators.append({
                'type': 'INFORMATION_DISCLOSURE',
                'detail': 'Server error with stack trace / exception info',
                'severity': 'MEDIUM'
            })

        # 2. Potential auth bypass -- userinfo/introspect returns success
        #    without error markers
        if status == 200 and endpoint in ('userinfo', 'introspect',
                                          'introspection'):
            if 'invalid' not in body_lower and 'error' not in body_lower:
                if 'sub' in body_lower or 'active' in body_lower:
                    indicators.append({
                        'type': 'POTENTIAL_AUTH_BYPASS',
                        'detail': f'{endpoint} returned successful data',
                        'severity': 'HIGH'
                    })

        # 3. Injection error indicators
        if any(kw in body_lower for kw in ['sql', 'syntax error',
                                             'database', 'query',
                                             'sqlalchemy']):
            indicators.append({
                'type': 'INJECTION_ERROR',
                'detail': 'Potential injection vulnerability',
                'severity': 'HIGH'
            })

        # 4. Timing anomaly
        response_time = response.get('response_time', 0)
        if response_time > 3000 and endpoint in ('token', 'authorization',
                                                   'login', 'password'):
            indicators.append({
                'type': 'TIMING_ANOMALY',
                'detail': f'Slow response on auth endpoint ({response_time:.0f}ms)',
                'severity': 'LOW'
            })

        if indicators:
            return {
                'timestamp': time.time(),
                'endpoint': endpoint,
                'status': status,
                'indicators': indicators
            }
        return None

    # ------------------------------------------------------------------
    # Crash detection via docker logs
    # ------------------------------------------------------------------
    def check_for_crashes(self, container_name: str = None) -> List[Dict]:
        """
        Check Docker container logs for crash/exception patterns.

        Uses ``self.error_patterns.detect_crash`` if available.

        Args:
            container_name: Override the stored container name.

        Returns:
            List of newly detected crash event dicts.
        """
        cname = container_name or self.container_name
        if not cname or self.error_patterns is None:
            return []

        try:
            result = subprocess.run(
                ['docker', 'logs', '--tail', '500', cname],
                capture_output=True, text=True, timeout=10
            )
            logs = result.stdout + result.stderr

            crash = self.error_patterns.detect_crash(logs)
            if crash and crash not in self.crash_events:
                crash['timestamp'] = time.time()
                crash['container'] = cname
                self.crash_events.append(crash)
                return [crash]
        except Exception:
            pass
        return []

    # ------------------------------------------------------------------
    # Coverage collection
    # ------------------------------------------------------------------
    def collect_coverage(self) -> Dict:
        """
        Collect and return current state-based coverage metrics.

        Returns a dict (GoCoverageData-like) with coverage percentages,
        state counts, and module-level breakdown.
        """
        coverage = self._get_state_based_coverage()

        # Track peak
        if coverage.get('coverage_percentage', 0.0) > self.max_coverage:
            self.max_coverage = coverage['coverage_percentage']

        # Store snapshot
        self.coverage_history.append(coverage)

        return coverage

    def _get_state_based_coverage(self) -> Dict:
        """
        Multi-dimensional weighted coverage calculation.

        Dimensions:
          - Unique state count
          - Response-code diversity
          - Endpoint coverage (with importance weights)
          - Error-pattern diversity
          - Security findings
          - Security-path coverage
          - Vulnerability indicators
        """
        unique_state_count = len(self.unique_states)
        response_diversity = len(self.response_codes)
        endpoint_diversity = len(self.endpoint_hits)
        error_pattern_diversity = len(set(self.error_patterns_seen))
        security_finding_count = len(self.security_findings)
        security_path_count = len(self.security_paths_covered)
        vuln_indicator_count = len(self.vulnerability_indicators)

        # Weighted endpoint coverage
        weighted_endpoint_coverage = 0.0
        for endpoint, hits in self.endpoint_hits.items():
            weight = ENDPOINT_IMPORTANCE.get(endpoint, 1.0)
            weighted_endpoint_coverage += min(hits, 10) * weight

        instructions_covered = (
            unique_state_count * 3
            + weighted_endpoint_coverage * 8
            + error_pattern_diversity * 5
            + security_finding_count * 20
            + security_path_count * 15
            + vuln_indicator_count * 25
            + response_diversity * 2
        )

        SECURITY_PATH_ESTIMATE = 100
        instructions_total = max(
            PYTHON_STATE_SPACE_ESTIMATE + SECURITY_PATH_ESTIMATE,
            instructions_covered + 100
        )

        coverage_percentage = min(
            100.0,
            (instructions_covered / instructions_total) * 100 if instructions_total > 0 else 0.0
        )

        module_coverage = {
            'state_exploration': min(100.0, unique_state_count * 5),
            'endpoint_coverage': min(100.0, endpoint_diversity * 15),
            'error_discovery': min(100.0, error_pattern_diversity * 10),
            'security_testing': min(100.0, security_finding_count * 25),
            'response_diversity': min(100.0, response_diversity * 8),
            'security_paths': min(100.0, security_path_count * 20),
            'vulnerability_indicators': min(100.0, vuln_indicator_count * 30),
        }

        return {
            'lines_covered': instructions_covered,
            'lines_total': instructions_total,
            'branches_covered': 0,
            'branches_total': 0,
            'methods_covered': 0,
            'methods_total': 0,
            'classes_covered': 0,
            'classes_total': 0,
            'instructions_covered': instructions_covered,
            'instructions_total': instructions_total,
            'coverage_percentage': coverage_percentage,
            'endpoint_coverage': dict(self.endpoint_hits),
            'error_pattern_coverage': dict(Counter(self.error_patterns_seen)),
            'module_coverage': module_coverage,
            # Snapshot metadata
            'snapshot_timestamp': time.time(),
            'execution_count': self.execution_count,
        }

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------
    def generate_report(self, output_dir: str = None) -> Optional[str]:
        """
        Write a JSON coverage report to disk.

        Args:
            output_dir: Override the default report directory.

        Returns:
            Path to the written report, or None on failure.
        """
        coverage = self.collect_coverage()
        if not coverage:
            return None

        out_dir = output_dir or self.report_dir
        os.makedirs(out_dir, exist_ok=True)

        timestamp = time.strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(out_dir, f'coverage_{timestamp}.json')

        report_data = {
            **coverage,
            'state_metrics': {
                'unique_states': len(self.unique_states),
                'response_codes': dict(self.response_codes),
                'endpoint_hits': self.endpoint_hits,
                'error_patterns': dict(Counter(self.error_patterns_seen)),
                'security_findings': len(self.security_findings),
                'crash_events': len(self.crash_events),
                'vulnerability_indicators': len(self.vulnerability_indicators),
                'total_executions': self.execution_count,
            },
            'security_findings': self.security_findings[-20:],
            'crash_events': self.crash_events,
        }

        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        return report_path

    # ------------------------------------------------------------------
    # Dump coverage (no-op for Python)
    # ------------------------------------------------------------------
    def dump_coverage(self) -> bool:
        """
        No-op for Python targets -- there is no runtime coverage
        instrumentation to flush.  Always returns True.
        """
        return True

    # ------------------------------------------------------------------
    # Reset
    # ------------------------------------------------------------------
    def reset(self) -> None:
        """Clear all state tracking for a new fuzzing session."""
        self.unique_states.clear()
        self.endpoint_hits.clear()
        self.response_codes.clear()
        self.error_patterns_seen.clear()
        self.security_findings.clear()
        self.security_paths_covered.clear()
        self.vulnerability_indicators.clear()

        self.execution_count = 0
        self.coverage_history.clear()
        self.baseline_coverage = None
        self.max_coverage = 0.0
        self.crash_events.clear()

    # ------------------------------------------------------------------
    # Coverage gain
    # ------------------------------------------------------------------
    def get_coverage_gain(self, previous: Dict = None) -> float:
        """
        Compute the coverage percentage gain between two snapshots.

        Args:
            previous: A previous coverage dict (as returned by
                      ``collect_coverage``).  Falls back to the
                      stored baseline.

        Returns:
            Absolute difference in coverage_percentage.
        """
        if not self.coverage_history:
            return 0.0

        current_pct = self.coverage_history[-1].get('coverage_percentage', 0.0)

        baseline = previous or self.baseline_coverage
        if baseline is None:
            return current_pct

        baseline_pct = baseline.get('coverage_percentage', 0.0)
        return current_pct - baseline_pct

    # ------------------------------------------------------------------
    # Security summary
    # ------------------------------------------------------------------
    def get_security_summary(self) -> Dict:
        """
        Return a summary dict of security-relevant findings.

        Keys: ``total_findings``, ``by_severity``, ``crash_count``,
        ``unique_error_patterns``, ``vulnerability_indicators``.
        """
        severity_counts: Dict[str, int] = {
            'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0
        }
        for finding in self.security_findings:
            sev = finding.get('severity', 'LOW')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        vuln_type_counts: Dict[str, int] = {}
        for vi in self.vulnerability_indicators:
            for indicator in vi.get('indicators', []):
                vtype = indicator.get('type', 'UNKNOWN')
                vuln_type_counts[vtype] = vuln_type_counts.get(vtype, 0) + 1

        return {
            'total_findings': len(self.security_findings),
            'by_severity': severity_counts,
            'crash_count': len(self.crash_events),
            'unique_error_patterns': len(set(self.error_patterns_seen)),
            'vulnerability_indicators': len(self.vulnerability_indicators),
            'vulnerability_types': vuln_type_counts,
        }
