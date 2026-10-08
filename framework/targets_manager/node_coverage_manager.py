#!/usr/bin/env python3
"""
Node Coverage Manager for OAuth Fuzzing Framework
Supports state-based coverage collection for Node.js/TypeScript OAuth targets
(node-oidc-provider, Logto).

Coverage collection is state-based only for now — no native V8 coverage
integration, but a hook is left for future addition.
"""

import os
import re
import json
import time
import hashlib
import subprocess
from typing import Dict, List, Optional, Set

import requests
from core.paths import PROJECT_ROOT


# ========== NODE-OIDC-PROVIDER ERROR PATTERN DATABASE ==========
class NodeOIDCErrorPatterns:
    """node-oidc-provider (Node.js) error pattern recognition database."""

    # Standard OAuth 2.0 / OIDC error codes
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
        'invalid_token': {'severity': 'HIGH', 'category': 'security'},
    }

    # node-oidc-provider specific error messages
    NODEOIDC_ERRORS = {
        'redirect_uri_mismatch': {'severity': 'HIGH', 'category': 'security'},
        'invalid_client_metadata': {'severity': 'MEDIUM', 'category': 'config'},
        'invalid code verifier': {'severity': 'HIGH', 'category': 'security'},
        'pkce verification failed': {'severity': 'HIGH', 'category': 'security'},
        'invalid_target': {'severity': 'MEDIUM', 'category': 'protocol'},
        'request_not_supported': {'severity': 'LOW', 'category': 'protocol'},
        'interaction_expired': {'severity': 'MEDIUM', 'category': 'session'},
        'session_not_found': {'severity': 'MEDIUM', 'category': 'session'},
        'authorization_request_expired': {'severity': 'LOW', 'category': 'session'},
        'invalid_authorization_code': {'severity': 'HIGH', 'category': 'security'},
        'code already exchanged': {'severity': 'HIGH', 'category': 'security'},
        'expired authorization code': {'severity': 'LOW', 'category': 'session'},
        'invalid redirect_uri': {'severity': 'HIGH', 'category': 'security'},
        'client not found': {'severity': 'MEDIUM', 'category': 'config'},
        'unsupported_response_mode': {'severity': 'LOW', 'category': 'protocol'},
        'consent required': {'severity': 'LOW', 'category': 'flow'},
        'login required': {'severity': 'LOW', 'category': 'flow'},
        'account_selection_required': {'severity': 'LOW', 'category': 'flow'},
        'unmet_authentication_requirements': {'severity': 'MEDIUM', 'category': 'security'},
        'insufficient_scope': {'severity': 'MEDIUM', 'category': 'security'},
        'token expired': {'severity': 'LOW', 'category': 'token'},
        'invalid code challenge method': {'severity': 'HIGH', 'category': 'security'},
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
        r'UnhandledPromiseRejection',
        r'FATAL ERROR',
        r'heap out of memory',
        r'RangeError',
        r'TypeError:',
        r'ECONNREFUSED',
        r'ENOENT',
        r'ENOMEM',
        r'SystemError',
        r'ERR_ASSERTION',
        r'node.*crashed',
        r'CALL_AND_RETRY_LAST',
        r'Fatal process',
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

        # Check status code
        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        # Check OAuth errors
        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        # Check node-oidc-provider specific errors
        for error, meta in cls.NODEOIDC_ERRORS.items():
            if error.lower() in body_lower:
                result['patterns_matched'].append(f'nodeoidc:{error}')
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
        """Detect Node.js crash patterns in logs."""
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


# ========== LOGTO ERROR PATTERN DATABASE ==========
class LogtoErrorPatterns:
    """Logto (TypeScript/Node.js OIDC provider) error pattern recognition database.

    Logto uses the panva oidc-provider library under the hood, so many error
    patterns overlap with NodeOIDCErrorPatterns. This class adds Logto-specific
    error signatures on top of the standard OAuth2/OIDC error superset.
    """

    # Standard OAuth 2.0 / OIDC error codes (standard 10 + interaction_required, login_required)
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
        'invalid_token': {'severity': 'HIGH', 'category': 'security'},
        'interaction_required': {'severity': 'LOW', 'category': 'flow'},
        'login_required': {'severity': 'LOW', 'category': 'flow'},
    }

    # Logto-specific error messages
    LOGTO_ERRORS = {
        'redirect_uri_mismatch': {'severity': 'HIGH', 'category': 'security'},
        'invalid code_verifier': {'severity': 'HIGH', 'category': 'security'},
        'pkce verification failed': {'severity': 'HIGH', 'category': 'security'},
        'session.not_found': {'severity': 'MEDIUM', 'category': 'session'},
        'authorization code expired': {'severity': 'LOW', 'category': 'session'},
        'code already exchanged': {'severity': 'HIGH', 'category': 'security'},
        'client not found': {'severity': 'MEDIUM', 'category': 'config'},
        'invalid redirect_uri': {'severity': 'HIGH', 'category': 'security'},
        'unsupported_response_mode': {'severity': 'LOW', 'category': 'protocol'},
        'consent required': {'severity': 'LOW', 'category': 'flow'},
        'unmet_authentication_requirements': {'severity': 'MEDIUM', 'category': 'security'},
        'insufficient_scope': {'severity': 'MEDIUM', 'category': 'security'},
        'token expired': {'severity': 'LOW', 'category': 'token'},
        'invalid code_challenge_method': {'severity': 'HIGH', 'category': 'security'},
        'session_expired': {'severity': 'MEDIUM', 'category': 'session'},
        'invalid_client_metadata': {'severity': 'MEDIUM', 'category': 'config'},
        'session_not_found': {'severity': 'MEDIUM', 'category': 'session'},
        'expired authorization code': {'severity': 'LOW', 'category': 'session'},
        'invalid_authorization_code': {'severity': 'HIGH', 'category': 'security'},
        'invalid_client_id': {'severity': 'HIGH', 'category': 'security'},
        'parse_error': {'severity': 'LOW', 'category': 'info'},
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
        r'UnhandledPromiseRejection',
        r'FATAL ERROR',
        r'heap out of memory',
        r'RangeError',
        r'TypeError:',
        r'ECONNREFUSED',
        r'ENOENT',
        r'ENOMEM',
        r'SystemError',
        r'ERR_ASSERTION',
        r'node.*crashed',
        r'CALL_AND_RETRY_LAST',
        r'Fatal process',
        r'ZodError',
        r'RequestError',
        r'KnexError',
        r'DatabaseError',
        r'SlonikError',
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

        # Check status code
        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        # Check OAuth errors
        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        # Check Logto-specific errors
        for error, meta in cls.LOGTO_ERRORS.items():
            if error.lower() in body_lower:
                result['patterns_matched'].append(f'logto:{error}')
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
        """Detect Node.js crash patterns in logs."""
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


# ========== NODE COVERAGE MANAGER ==========

# Estimated OAuth state space for Node.js targets
NODE_STATE_SPACE_ESTIMATE = 1000

# Endpoint importance weights — mirrors GoCoverageManager weights
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


class NodeCoverageManager:
    """
    Coverage manager for Node.js/TypeScript OAuth targets (node-oidc-provider, Logto).

    State-based coverage only for now. A hook is left for future native V8
    coverage integration via ``NODE_V8_COVERAGE``.

    Public interface mirrors GoCoverageManager so that target managers can
    swap between the two transparently.
    """

    def __init__(self, work_dir: str,
                 container_name: str = 'node-fuzz-coverage',
                 base_url: str = 'http://localhost:3000'):
        """Initialize Node coverage manager.

        Args:
            work_dir: Working directory for coverage data and reports.
            container_name: Docker container name for log-based crash detection.
            base_url: Base URL of the running OAuth target.
        """
        self.work_dir = work_dir
        self.container_name = container_name
        self.base_url = base_url

        # Coverage directories
        self.coverage_dir = os.path.join(work_dir, 'coverage')
        self.report_dir = os.path.join(work_dir, 'coverage_reports')

        # Ensure directories exist
        os.makedirs(self.coverage_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)

        # State tracking (same as PythonCoverageManager / GoCoverageManager)
        self.unique_states: Set[str] = set()
        self.endpoint_hits: Dict[str, int] = {}
        self.response_codes: Set[int] = set()
        self.error_patterns_seen: Dict[str, int] = {}
        self.security_findings: List[Dict] = []
        self.security_paths_covered: Set[str] = set()
        self.vulnerability_indicators: List[Dict] = []

        # Coverage history and peak tracking
        self.max_coverage: Optional[Dict] = None
        self.coverage_history: List[Dict] = []

        # Execution counter
        self.execution_count: int = 0

        # Crash events
        self.crash_events: List[Dict] = []

        # Error pattern recognizer — set by target manager to either
        # NodeOIDCErrorPatterns or LogtoErrorPatterns
        self.error_patterns = NodeOIDCErrorPatterns

        # Hook placeholder for future native V8 coverage
        # When enabled, set env: NODE_V8_COVERAGE=/path/to/coverage
        self._v8_coverage_enabled = False
        self._v8_coverage_dir = os.path.join(self.coverage_dir, 'v8')

    # ------------------------------------------------------------------
    # Public interface (mirrors GoCoverageManager)
    # ------------------------------------------------------------------

    def track_response(self, response: Dict, endpoint: str = '') -> Dict:
        """Record a response, classify errors, detect security indicators.

        Args:
            response: Dict with keys ``status_code``, ``body``, ``headers``,
                      ``content_type``, ``error``, ``response_time``.
            endpoint: Optional endpoint label for weighted coverage.

        Returns:
            Dict with ``is_new_state``, ``classification``, ``weight_modifier``.
        """
        self.execution_count += 1

        status = response.get('status_code', 0)
        content_type = response.get('content_type', '')
        body = response.get('body', '')
        error = response.get('error', '')
        headers = response.get('headers', {})

        # --- Endpoint tracking ---
        if endpoint:
            self.endpoint_hits[endpoint] = self.endpoint_hits.get(endpoint, 0) + 1

        # --- State signature (unique state detection) ---
        body_hash = hashlib.md5((body[:500] if body else '').encode('utf-8')).hexdigest()[:8]
        state_sig = f"{endpoint or 'unknown'}:{status}:{content_type}:{body_hash}"
        is_new_state = state_sig not in self.unique_states
        self.unique_states.add(state_sig)
        self.response_codes.add(status)

        # --- Error classification ---
        classification = self.error_patterns.classify_error(response)

        for pattern in classification['patterns_matched']:
            self.error_patterns_seen[pattern] = self.error_patterns_seen.get(pattern, 0) + 1

        # --- Security finding tracking ---
        security_path_new = None
        if classification['is_security_relevant']:
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
            security_path_new = security_path

        # --- Vulnerability indicator detection ---
        vuln_indicator = self._detect_vulnerability_indicator(response)
        if vuln_indicator:
            self.vulnerability_indicators.append(vuln_indicator)

        return {
            'is_new_state': is_new_state,
            'classification': classification,
            'weight_modifier': classification['weight_modifier'],
            'security_path_new': security_path_new
        }

    def _detect_vulnerability_indicator(self, response: Dict) -> Optional[Dict]:
        """Check for information disclosure, auth bypass, injection, and timing anomalies."""
        body = str(response.get('body', ''))
        body_lower = body.lower()
        status = response.get('status_code', 0)
        endpoint = response.get('endpoint', '')

        indicators = []

        # Information disclosure: stack trace or error detail in 5xx response
        if status >= 500 and any(kw in body_lower for kw in ['stack', 'trace', 'error:', 'at ', 'unhandled']):
            indicators.append({
                'type': 'INFORMATION_DISCLOSURE',
                'detail': 'Server error with stack trace or internal detail',
                'severity': 'MEDIUM'
            })

        # Potential auth bypass: protected endpoint returning 200 without error markers
        if status == 200 and endpoint in ('userinfo', 'introspect', 'introspection'):
            if 'error' not in body_lower and 'invalid' not in body_lower:
                if 'sub' in body_lower or 'active' in body_lower:
                    indicators.append({
                        'type': 'POTENTIAL_AUTH_BYPASS',
                        'detail': f'{endpoint} returned successful data without clear auth',
                        'severity': 'HIGH'
                    })

        # Injection error indicators
        if any(kw in body_lower for kw in ['sql', 'syntax error', 'database', 'query', 'sequelize', 'knex', 'slonik']):
            indicators.append({
                'type': 'INJECTION_ERROR',
                'detail': 'Potential injection-related error message',
                'severity': 'HIGH'
            })

        # Timing anomaly
        response_time = response.get('response_time', 0)
        if response_time > 3000 and endpoint in ('token', 'authorization', 'login'):
            indicators.append({
                'type': 'TIMING_ANOMALY',
                'detail': f'Slow response on auth endpoint ({response_time}ms)',
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

    def check_for_crashes(self, container_name: str = None) -> List[Dict]:
        """Check Docker container logs for Node.js crash patterns.

        Args:
            container_name: Override the default container name.

        Returns:
            List of newly detected crash event dicts.
        """
        cname = container_name or self.container_name
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

    def collect_coverage(self) -> Dict:
        """Collect and return coverage data dict.

        Returns:
            Dict with coverage metrics, state metrics, and security summary.
        """
        state_coverage = self._get_state_based_coverage()

        # Update peak tracking
        pct = state_coverage.get('coverage_percentage', 0.0)
        if self.max_coverage is None or pct > self.max_coverage.get('coverage_percentage', 0.0):
            self.max_coverage = dict(state_coverage)

        self.coverage_history.append(state_coverage)
        return state_coverage

    def _get_state_based_coverage(self) -> Dict:
        """Multi-dimensional weighted state-based coverage calculation.

        Mirrors the GoCoverageManager weighting scheme but adapted for
        Node.js targets with ENDPOINT_IMPORTANCE weights.
        """
        unique_state_count = len(self.unique_states)
        response_diversity = len(self.response_codes)
        endpoint_diversity = len(self.endpoint_hits)
        error_pattern_diversity = len(self.error_patterns_seen)
        security_finding_count = len(self.security_findings)
        security_path_count = len(self.security_paths_covered)
        vuln_indicator_count = len(self.vulnerability_indicators)

        # Weighted endpoint coverage
        weighted_endpoint_coverage = 0.0
        for endpoint, hits in self.endpoint_hits.items():
            weight = ENDPOINT_IMPORTANCE.get(endpoint, 1.0)
            weighted_endpoint_coverage += min(hits, 10) * weight

        # Weighted coverage calculation
        instructions_covered = (
            unique_state_count * 3 +
            weighted_endpoint_coverage * 8 +
            error_pattern_diversity * 5 +
            security_finding_count * 20 +
            security_path_count * 15 +
            vuln_indicator_count * 25 +
            response_diversity * 2
        )

        SECURITY_PATH_ESTIMATE = 100
        instructions_total = max(
            NODE_STATE_SPACE_ESTIMATE + SECURITY_PATH_ESTIMATE,
            instructions_covered + 100
        )

        if instructions_total > 0:
            coverage_percentage = min(100.0, (instructions_covered / instructions_total) * 100)
        else:
            coverage_percentage = 0.0

        return {
            'lines_covered': instructions_covered,
            'lines_total': instructions_total,
            'instructions_covered': instructions_covered,
            'instructions_total': instructions_total,
            'coverage_percentage': coverage_percentage,
            'state_metrics': {
                'unique_states': unique_state_count,
                'response_codes': sorted(self.response_codes),
                'endpoint_hits': dict(self.endpoint_hits),
                'error_patterns': dict(self.error_patterns_seen),
                'security_findings': security_finding_count,
                'security_paths': security_path_count,
                'vulnerability_indicators': vuln_indicator_count,
                'crash_events': len(self.crash_events),
                'total_executions': self.execution_count,
            },
            'module_coverage': {
                'state_exploration': min(100.0, unique_state_count * 5),
                'endpoint_coverage': min(100.0, endpoint_diversity * 15),
                'error_discovery': min(100.0, error_pattern_diversity * 10),
                'security_testing': min(100.0, security_finding_count * 25),
                'response_diversity': min(100.0, response_diversity * 8),
                'security_paths': min(100.0, security_path_count * 20),
                'vulnerability_indicators': min(100.0, vuln_indicator_count * 30),
            },
            'endpoint_coverage': dict(self.endpoint_hits),
            'error_pattern_coverage': dict(self.error_patterns_seen),
        }

    def generate_report(self, output_dir: str = None) -> Optional[str]:
        """Write a JSON coverage report to disk.

        Args:
            output_dir: Directory to write the report. Defaults to
                        ``self.report_dir``.

        Returns:
            Path to the written report file, or None on failure.
        """
        out_dir = output_dir or self.report_dir
        os.makedirs(out_dir, exist_ok=True)

        coverage = self.collect_coverage()

        timestamp = time.strftime('%Y%m%d_%H%M%S')
        report_path = os.path.join(out_dir, f'coverage_{timestamp}.json')

        report_data = {
            'timestamp': timestamp,
            'target_type': 'node',
            'container_name': self.container_name,
            'base_url': self.base_url,
            **coverage,
            'security_findings': self.security_findings[-20:],
            'crash_events': self.crash_events,
        }

        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        return report_path

    def dump_coverage(self) -> bool:
        """No-op for now — native V8 coverage hook placeholder.

        Returns:
            True always (placeholder success).
        """
        # Check for crashes while we're here
        self.check_for_crashes()
        self.collect_coverage()
        return True

    def reset(self) -> None:
        """Clear all state tracking for a new fuzzing session."""
        self.unique_states.clear()
        self.endpoint_hits.clear()
        self.response_codes.clear()
        self.error_patterns_seen.clear()
        self.security_findings.clear()
        self.security_paths_covered.clear()
        self.vulnerability_indicators.clear()
        self.crash_events.clear()
        self.coverage_history.clear()
        self.max_coverage = None
        self.execution_count = 0

    def get_coverage_gain(self, previous: Dict = None) -> float:
        """Compute coverage gain over a previous snapshot.

        Args:
            previous: Dict from a prior ``collect_coverage()`` call. If None,
                      uses the first entry in ``coverage_history``.

        Returns:
            Coverage percentage delta.
        """
        if not self.coverage_history:
            return 0.0

        current_pct = self.coverage_history[-1].get('coverage_percentage', 0.0)

        if previous is not None:
            prev_pct = previous.get('coverage_percentage', 0.0)
        elif len(self.coverage_history) > 1:
            prev_pct = self.coverage_history[0].get('coverage_percentage', 0.0)
        else:
            return current_pct

        return current_pct - prev_pct

    def get_security_summary(self) -> Dict:
        """Return a summary of security-relevant findings.

        Returns:
            Dict with ``total_findings``, ``by_severity``, ``crash_count``,
            ``unique_error_patterns``.
        """
        severity_counts: Dict[str, int] = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.security_findings:
            sev = finding.get('severity', 'LOW')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            'total_findings': len(self.security_findings),
            'by_severity': severity_counts,
            'crash_count': len(self.crash_events),
            'unique_error_patterns': len(self.error_patterns_seen),
        }
