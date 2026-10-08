#!/usr/bin/env python3
"""
Go Coverage Manager for OAuth Fuzzing Framework
Supports native Go coverage collection for Go-based targets like Authelia.

Go 1.20+ supports application coverage (not just test coverage) via:
1. Build with: go build -cover -o binary ./cmd/...
2. Set environment: GOCOVERDIR=/path/to/coverage
3. Run application, coverage profiles written to GOCOVERDIR
4. Parse with: go tool covdata percent -i=/path/to/coverage
"""

import subprocess
import os
import json
import time
import shutil
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from core.paths import PROJECT_ROOT


@dataclass
class GoCoverageData:
    """Go coverage data structure matching CoverageData interface"""
    lines_covered: int = 0
    lines_total: int = 0
    branches_covered: int = 0
    branches_total: int = 0
    methods_covered: int = 0
    methods_total: int = 0
    classes_covered: int = 0
    classes_total: int = 0
    instructions_covered: int = 0
    instructions_total: int = 0
    coverage_percentage: float = 0.0
    
    # Go-specific fields
    packages_covered: int = 0
    packages_total: int = 0
    statements_covered: int = 0
    statements_total: int = 0
    package_coverage: Dict[str, float] = field(default_factory=dict)
    
    # Module-level coverage for granular tracking
    module_coverage: Dict[str, float] = field(default_factory=dict)
    hot_methods: Set[str] = field(default_factory=set)
    
    # Authelia-specific tracking
    endpoint_coverage: Dict[str, int] = field(default_factory=dict)
    error_pattern_coverage: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        return {
            'lines_covered': self.lines_covered,
            'lines_total': self.lines_total,
            'coverage_percentage': self.coverage_percentage,
            'packages_covered': self.packages_covered,
            'packages_total': self.packages_total,
            'statements_covered': self.statements_covered,
            'statements_total': self.statements_total,
            'package_coverage': self.package_coverage,
            'endpoint_coverage': self.endpoint_coverage,
            'error_pattern_coverage': self.error_pattern_coverage
        }


# ========== AUTHELIA ERROR PATTERN DATABASE ==========
class AutheliaErrorPatterns:
    """Authelia-specific error pattern recognition database"""
    
    # OAuth/OIDC Error Codes (RFC 6749 + Authelia-specific)
    OAUTH_ERRORS = {
        'invalid_request': {'severity': 'MEDIUM', 'category': 'protocol'},
        'unauthorized_client': {'severity': 'HIGH', 'category': 'security'},
        'access_denied': {'severity': 'MEDIUM', 'category': 'access'},
        'unsupported_response_type': {'severity': 'LOW', 'category': 'protocol'},
        'invalid_scope': {'severity': 'MEDIUM', 'category': 'protocol'},
        'server_error': {'severity': 'CRITICAL', 'category': 'server'},
        'temporarily_unavailable': {'severity': 'LOW', 'category': 'server'},
        'invalid_client': {'severity': 'HIGH', 'category': 'security'},
        'invalid_grant': {'severity': 'HIGH', 'category': 'security'},
        'unsupported_grant_type': {'severity': 'LOW', 'category': 'protocol'},
        'consent_required': {'severity': 'LOW', 'category': 'flow'},
        'interaction_required': {'severity': 'LOW', 'category': 'flow'},
        'login_required': {'severity': 'LOW', 'category': 'flow'},
    }
    
    # Authelia-specific error messages
    AUTHELIA_ERRORS = {
        'authentication failed': {'severity': 'MEDIUM', 'category': 'auth'},
        'user not found': {'severity': 'MEDIUM', 'category': 'auth'},
        'invalid credentials': {'severity': 'MEDIUM', 'category': 'auth'},
        'session expired': {'severity': 'LOW', 'category': 'session'},
        'session not found': {'severity': 'MEDIUM', 'category': 'session'},
        'totp validation failed': {'severity': 'MEDIUM', 'category': '2fa'},
        'webauthn validation failed': {'severity': 'MEDIUM', 'category': '2fa'},
        'second factor required': {'severity': 'LOW', 'category': '2fa'},
        'banned': {'severity': 'LOW', 'category': 'regulation'},
        'regulated': {'severity': 'LOW', 'category': 'regulation'},
        'redirect uri mismatch': {'severity': 'HIGH', 'category': 'security'},
        'pkce verification failed': {'severity': 'HIGH', 'category': 'security'},
        'code challenge required': {'severity': 'MEDIUM', 'category': 'security'},
        'invalid code verifier': {'severity': 'HIGH', 'category': 'security'},
        'token revoked': {'severity': 'LOW', 'category': 'token'},
        'token expired': {'severity': 'LOW', 'category': 'token'},
        'invalid token': {'severity': 'MEDIUM', 'category': 'token'},
        'client secret mismatch': {'severity': 'HIGH', 'category': 'security'},
        'consent denied': {'severity': 'LOW', 'category': 'flow'},
    }
    
    # HTTP Status Code patterns
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
        422: {'meaning': 'unprocessable', 'weight': 1.5},
        429: {'meaning': 'rate_limited', 'weight': 1.2},
        500: {'meaning': 'server_error', 'weight': 3.0},
        502: {'meaning': 'bad_gateway', 'weight': 2.5},
        503: {'meaning': 'unavailable', 'weight': 2.0},
    }
    
    # Crash/Panic patterns (Go-specific)
    CRASH_PATTERNS = [
        r'panic:',
        r'runtime error:',
        r'fatal error:',
        r'goroutine \d+ \[running\]:',
        r'stack trace:',
        r'nil pointer dereference',
        r'index out of range',
        r'invalid memory address',
        r'deadlock',
        r'SIGABRT',
        r'SIGSEGV',
    ]
    
    @classmethod
    def classify_error(cls, response: Dict) -> Dict:
        """Classify an error response and return error metadata"""
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
        
        # Check Authelia-specific errors
        for error, meta in cls.AUTHELIA_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'authelia:{error}')
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
        """Detect Go crash patterns in logs"""
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


# ========== CASDOOR ERROR PATTERN DATABASE ==========
class CasdoorErrorPatterns:
    """Casdoor-specific error pattern recognition database."""

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

    CASDOOR_ERRORS = {
        'authentication failed': {'severity': 'MEDIUM', 'category': 'auth'},
        'user not found': {'severity': 'MEDIUM', 'category': 'auth'},
        'invalid credentials': {'severity': 'MEDIUM', 'category': 'auth'},
        'password error': {'severity': 'HIGH', 'category': 'security'},
        'session expired': {'severity': 'LOW', 'category': 'session'},
        'token expired': {'severity': 'LOW', 'category': 'token'},
        'invalid token': {'severity': 'MEDIUM', 'category': 'token'},
        'code is used': {'severity': 'LOW', 'category': 'token'},
        'redirect uri mismatch': {'severity': 'HIGH', 'category': 'security'},
        'pkce verification failed': {'severity': 'HIGH', 'category': 'security'},
        'client secret mismatch': {'severity': 'HIGH', 'category': 'security'},
        'app not found': {'severity': 'MEDIUM', 'category': 'config'},
        'org not found': {'severity': 'MEDIUM', 'category': 'config'},
        'captcha': {'severity': 'LOW', 'category': 'flow'},
        'operation not allowed': {'severity': 'MEDIUM', 'category': 'access'},
        'access denied': {'severity': 'HIGH', 'category': 'security'},
        'permission denied': {'severity': 'HIGH', 'category': 'security'},
        'forbidden': {'severity': 'HIGH', 'category': 'security'},
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
        429: {'meaning': 'rate_limited', 'weight': 1.2},
        500: {'meaning': 'server_error', 'weight': 3.0},
        502: {'meaning': 'bad_gateway', 'weight': 2.5},
        503: {'meaning': 'unavailable', 'weight': 2.0},
    }

    CRASH_PATTERNS = [
        r'panic:',
        r'runtime error:',
        r'fatal error:',
        r'goroutine \d+ \[running\]:',
        r'nil pointer dereference',
        r'index out of range',
        r'invalid memory address',
        r'deadlock',
        r'SIGABRT',
        r'SIGSEGV',
        r'BeeGo.*panic',
        r'XORM.*error',
    ]

    @classmethod
    def classify_error(cls, response: Dict) -> Dict:
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

        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        for error, meta in cls.CASDOOR_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'casdoor:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        if result['is_security_relevant']:
            result['weight_modifier'] *= 2.0

        return result

    @classmethod
    def detect_crash(cls, log_content: str) -> Optional[Dict]:
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


# ========== ORY HYDRA ERROR PATTERN DATABASE ==========
class OryHydraErrorPatterns:
    """Ory Hydra-specific error pattern recognition database."""

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
        'consent_required': {'severity': 'LOW', 'category': 'flow'},
        'interaction_required': {'severity': 'LOW', 'category': 'flow'},
        'login_required': {'severity': 'LOW', 'category': 'flow'},
        'request_not_supported': {'severity': 'LOW', 'category': 'protocol'},
        'request_uri_not_supported': {'severity': 'LOW', 'category': 'protocol'},
    }

    HYDRA_ERRORS = {
        'invalid_client': {'severity': 'HIGH', 'category': 'security'},
        'client not found': {'severity': 'MEDIUM', 'category': 'config'},
        'client secret mismatch': {'severity': 'HIGH', 'category': 'security'},
        'redirect_uri mismatch': {'severity': 'HIGH', 'category': 'security'},
        'pkce verification failed': {'severity': 'HIGH', 'category': 'security'},
        'code challenge required': {'severity': 'MEDIUM', 'category': 'security'},
        'invalid code verifier': {'severity': 'HIGH', 'category': 'security'},
        'token expired': {'severity': 'LOW', 'category': 'token'},
        'invalid token': {'severity': 'MEDIUM', 'category': 'token'},
        'token revoked': {'severity': 'LOW', 'category': 'token'},
        'consent denied': {'severity': 'LOW', 'category': 'flow'},
        'login request not found': {'severity': 'MEDIUM', 'category': 'flow'},
        'consent request not found': {'severity': 'MEDIUM', 'category': 'flow'},
        'subject mismatch': {'severity': 'HIGH', 'category': 'security'},
        'audience mismatch': {'severity': 'HIGH', 'category': 'security'},
        'missing authorization header': {'severity': 'MEDIUM', 'category': 'auth'},
        'invalid authorization header': {'severity': 'MEDIUM', 'category': 'auth'},
        'csrf token is invalid': {'severity': 'MEDIUM', 'category': 'security'},
        'not_found': {'severity': 'LOW', 'category': 'routing'},
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
        r'panic:',
        r'runtime error:',
        r'fatal error:',
        r'goroutine \d+ \[running\]:',
        r'nil pointer dereference',
        r'index out of range',
        r'invalid memory address',
        r'deadlock',
        r'SIGABRT',
        r'SIGSEGV',
        r'An error occurred in the SQL',
        r'migration.*failed',
    ]

    @classmethod
    def classify_error(cls, response: Dict) -> Dict:
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

        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        for error, meta in cls.HYDRA_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'hydra:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        if result['is_security_relevant']:
            result['weight_modifier'] *= 2.0

        return result

    @classmethod
    def detect_crash(cls, log_content: str) -> Optional[Dict]:
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


# ========== ZITADEL ERROR PATTERN DATABASE ==========
class ZitadelErrorPatterns:
    """Zitadel-specific error pattern recognition database."""

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

    ZITADEL_ERRORS = {
        'auth failed': {'severity': 'MEDIUM', 'category': 'auth'},
        'user not found': {'severity': 'MEDIUM', 'category': 'auth'},
        'invalid credentials': {'severity': 'MEDIUM', 'category': 'auth'},
        'token expired': {'severity': 'LOW', 'category': 'token'},
        'invalid token': {'severity': 'MEDIUM', 'category': 'token'},
        'token revoked': {'severity': 'LOW', 'category': 'token'},
        'redirect uri mismatch': {'severity': 'HIGH', 'category': 'security'},
        'pkce verification failed': {'severity': 'HIGH', 'category': 'security'},
        'client secret mismatch': {'severity': 'HIGH', 'category': 'security'},
        'permission denied': {'severity': 'HIGH', 'category': 'security'},
        'forbidden': {'severity': 'HIGH', 'category': 'security'},
        'org not found': {'severity': 'MEDIUM', 'category': 'config'},
        'instance not found': {'severity': 'MEDIUM', 'category': 'config'},
        'mfa required': {'severity': 'LOW', 'category': '2fa'},
        'mfa not verified': {'severity': 'MEDIUM', 'category': '2fa'},
        'session not found': {'severity': 'MEDIUM', 'category': 'session'},
        'session expired': {'severity': 'LOW', 'category': 'session'},
        'idp not found': {'severity': 'MEDIUM', 'category': 'config'},
        'quota exceeded': {'severity': 'LOW', 'category': 'regulation'},
        'user is locked': {'severity': 'MEDIUM', 'category': 'security'},
        'Precondition': {'severity': 'MEDIUM', 'category': 'flow'},
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
        412: {'meaning': 'precondition_failed', 'weight': 2.0},
        429: {'meaning': 'rate_limited', 'weight': 1.2},
        500: {'meaning': 'server_error', 'weight': 3.0},
        502: {'meaning': 'bad_gateway', 'weight': 2.5},
        503: {'meaning': 'unavailable', 'weight': 2.0},
    }

    CRASH_PATTERNS = [
        r'panic:',
        r'runtime error:',
        r'fatal error:',
        r'goroutine \d+ \[running\]:',
        r'nil pointer dereference',
        r'index out of range',
        r'invalid memory address',
        r'deadlock',
        r'SIGABRT',
        r'SIGSEGV',
        r'gRPC.*panic',
        r'cockroachdb.*error',
    ]

    @classmethod
    def classify_error(cls, response: Dict) -> Dict:
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

        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        for error, meta in cls.ZITADEL_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'zitadel:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        if result['is_security_relevant']:
            result['weight_modifier'] *= 2.0

        return result

    @classmethod
    def detect_crash(cls, log_content: str) -> Optional[Dict]:
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


class AuthentikErrorPatterns:
    """Authentik (Python/Django) error pattern recognition database."""

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

        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        for error, meta in cls.AUTHENTIK_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'authentik:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        if result['is_security_relevant']:
            result['weight_modifier'] *= 2.0

        return result

    @classmethod
    def detect_crash(cls, log_content: str) -> Optional[Dict]:
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

        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        for error, meta in cls.SIMPLELOGIN_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'simplelogin:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        if result['is_security_relevant']:
            result['weight_modifier'] *= 2.0

        return result

    @classmethod
    def detect_crash(cls, log_content: str) -> Optional[Dict]:
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


class NodeOIDCErrorPatterns:
    """node-oidc-provider (Node.js) error pattern recognition database."""

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

        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        for error, meta in cls.NODEOIDC_ERRORS.items():
            if error.lower() in body_lower:
                result['patterns_matched'].append(f'nodeoidc:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        if result['is_security_relevant']:
            result['weight_modifier'] *= 2.0

        return result

    @classmethod
    def detect_crash(cls, log_content: str) -> Optional[Dict]:
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


class LogtoErrorPatterns:
    """Logto (TypeScript/Node.js OIDC provider) error pattern recognition database.

    Logto uses the panva oidc-provider library under the hood, so many error
    patterns overlap with NodeOIDCErrorPatterns. This class adds Logto-specific
    error signatures on top of the standard OAuth2/OIDC error superset.
    """

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

        if status_code in cls.STATUS_PATTERNS:
            result['weight_modifier'] = cls.STATUS_PATTERNS[status_code]['weight']

        for error, meta in cls.OAUTH_ERRORS.items():
            if error in body_lower:
                result['patterns_matched'].append(f'oauth:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        for error, meta in cls.LOGTO_ERRORS.items():
            if error.lower() in body_lower:
                result['patterns_matched'].append(f'logto:{error}')
                if meta['severity'] in ('HIGH', 'CRITICAL'):
                    result['severity'] = meta['severity']
                    result['is_security_relevant'] = True
                result['category'] = meta['category']

        if result['is_security_relevant']:
            result['weight_modifier'] *= 2.0

        return result

    @classmethod
    def detect_crash(cls, log_content: str) -> Optional[Dict]:
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


class GoCoverageManager:
    """
    Enhanced Coverage manager for Go-based targets (Authelia).
    Supports real Go instrumentation coverage and state-based coverage as fallback.
    Includes security-focused coverage gain calculations.
    """
    
    def __init__(self, work_dir: str = os.path.join(PROJECT_ROOT, 'targets_manager', 'authelia_service', 'work'),
                 coverage_mode: str = 'hybrid',
                 container_name: str = 'authelia-fuzz-coverage',
                 authelia_base_url: str = 'https://localhost:9091'):
        """Initialize Go coverage manager with hybrid mode support."""
        self.work_dir = work_dir
        self.coverage_mode = coverage_mode  # 'real', 'state', or 'hybrid'
        self.container_name = container_name
        self.authelia_base_url = authelia_base_url
        
        # Coverage directories
        self.coverage_dir = os.path.join(work_dir, 'coverage')
        self.container_coverage_dir = '/tmp/coverage'
        self.report_dir = os.path.join(work_dir, 'coverage_reports')
        
        # Ensure directories exist
        os.makedirs(self.coverage_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)
        
        # State tracking for state-based coverage
        self.unique_states: Set[str] = set()
        self.response_codes: Set[int] = set()
        self.endpoint_hits: Dict[str, int] = {}
        self.error_patterns_seen: Dict[str, int] = {}
        self.interesting_cases: List[Dict] = []
        self.execution_count: int = 0
        
        # Coverage history
        self.history: List[GoCoverageData] = []
        self.baseline_coverage: Optional[GoCoverageData] = None
        
        # Maximum coverage tracking
        self.max_coverage: Optional[GoCoverageData] = None
        self.peak_coverage_percentage: float = 0.0
        self.snapshot_count: int = 0
        
        # Security findings tracking
        self.security_findings: List[Dict] = []
        self.crash_events: List[Dict] = []
        
        # Error pattern recognizer
        self.error_patterns = AutheliaErrorPatterns()
        
        # NEW: Security-specific coverage tracking
        self.security_paths_covered: Set[str] = set()
        self.oauth_endpoint_coverage: Dict[str, Dict] = {}
        self.vulnerability_indicators: List[Dict] = []
        
        # NEW: OAuth endpoint importance weights for coverage calculation
        self._oauth_endpoint_weights = {
            'authorization': 1.5,
            'token': 2.0,
            'userinfo': 1.5,
            'introspection': 1.8,
            'revocation': 1.3,
            'firstfactor': 2.5,  # Authelia-specific high-value
            'secondfactor_totp': 3.0,
            'consent': 1.5,
            'logout': 1.2,
            'jwks': 1.0,
            'discovery': 0.8,
        }
    
    def setup_coverage_environment(self) -> Dict[str, str]:
        """Get environment variables needed for Go coverage collection."""
        return {
            'GOCOVERDIR': self.container_coverage_dir,
            'GOGC': '100',  # Garbage collection tuning
        }
    
    def get_docker_volume_mounts(self) -> List[str]:
        """Get Docker volume mount arguments for coverage collection."""
        return [
            '-v', f'{self.coverage_dir}:{self.container_coverage_dir}'
        ]
    
    def track_response(self, response: Dict, endpoint: str = None) -> Dict:
        """
        Enhanced response tracking with security-sensitive path detection.
        
        Returns classification result with weight modifier.
        """
        self.execution_count += 1
        
        status = response.get('status_code', 0)
        content_type = response.get('content_type', '')
        body = response.get('body', '')
        error = response.get('error', '')
        headers = response.get('headers', {})
        
        # Track endpoint hits with status breakdown
        if endpoint:
            self.endpoint_hits[endpoint] = self.endpoint_hits.get(endpoint, 0) + 1
            
            # Track endpoint-status combinations
            endpoint_key = f"{endpoint}:{status}"
            if endpoint_key not in self.oauth_endpoint_coverage:
                self.oauth_endpoint_coverage[endpoint_key] = {
                    'count': 0,
                    'first_seen': time.time(),
                    'last_seen': time.time(),
                    'is_new': True
                }
            else:
                self.oauth_endpoint_coverage[endpoint_key]['is_new'] = False
            self.oauth_endpoint_coverage[endpoint_key]['count'] += 1
            self.oauth_endpoint_coverage[endpoint_key]['last_seen'] = time.time()
        
        # Create detailed state signature
        body_hash = hash(body[:500] if body else '') % 100000
        state_sig = f"{endpoint or 'unknown'}:{status}:{content_type}:{body_hash}"
        is_new_state = state_sig not in self.unique_states
        self.unique_states.add(state_sig)
        self.response_codes.add(status)
        
        # Classify error patterns
        classification = self.error_patterns.classify_error(response)
        
        # Track error patterns
        for pattern in classification['patterns_matched']:
            self.error_patterns_seen[pattern] = self.error_patterns_seen.get(pattern, 0) + 1
        
        # Track security-relevant findings with enhanced detection
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
            
            # Track security path
            security_path = f"{endpoint}:{classification['category']}:{classification['severity']}"
            self.security_paths_covered.add(security_path)
        
        # NEW: Detect potential vulnerability indicators
        vuln_indicator = self._detect_vulnerability_indicator(response, endpoint, status)
        if vuln_indicator:
            self.vulnerability_indicators.append(vuln_indicator)
        
        return {
            'is_new_state': is_new_state,
            'classification': classification,
            'weight_modifier': classification['weight_modifier'],
            'security_path_new': security_path if classification['is_security_relevant'] else None
        }
    
    def _detect_vulnerability_indicator(self, response: Dict, endpoint: str, status: int) -> Optional[Dict]:
        """Detect potential vulnerability indicators from response"""
        body = str(response.get('body', ''))
        body_lower = body.lower()
        
        indicators = []
        
        # Server error with stack trace (information disclosure)
        if status >= 500 and ('stack' in body_lower or 'trace' in body_lower or 'panic' in body_lower):
            indicators.append({
                'type': 'INFORMATION_DISCLOSURE',
                'detail': 'Server error with stack trace',
                'severity': 'MEDIUM'
            })
        
        # Successful auth bypass indicators
        if status == 200 and endpoint in ('userinfo', 'introspection'):
            if 'invalid' not in body_lower and 'error' not in body_lower:
                if 'sub' in body_lower or 'active' in body_lower:
                    # This might indicate successful auth without proper credentials
                    indicators.append({
                        'type': 'POTENTIAL_AUTH_BYPASS',
                        'detail': f'{endpoint} returned successful data',
                        'severity': 'HIGH'
                    })
        
        # SQL/Injection error indicators
        if any(kw in body_lower for kw in ['sql', 'syntax error', 'database', 'query']):
            indicators.append({
                'type': 'INJECTION_ERROR',
                'detail': 'Potential injection vulnerability',
                'severity': 'HIGH'
            })
        
        # Timing-based indicators (slow response for auth)
        response_time = response.get('response_time', 0)
        if response_time > 3000 and endpoint in ('firstfactor', 'token'):
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

    def track_state(self, response: Dict) -> None:
        """Legacy method for backward compatibility."""
        self.track_response(response)
    
    def add_interesting_case(self, case: Dict) -> None:
        """Add an interesting case to tracking."""
        self.interesting_cases.append(case)
    
    def check_for_crashes(self) -> List[Dict]:
        """Check container logs for crash patterns."""
        try:
            result = subprocess.run(
                ['docker', 'logs', '--tail', '500', self.container_name],
                capture_output=True, text=True, timeout=10
            )
            logs = result.stdout + result.stderr
            
            crash = self.error_patterns.detect_crash(logs)
            if crash and crash not in self.crash_events:
                crash['timestamp'] = time.time()
                self.crash_events.append(crash)
                return [crash]
        except Exception:
            pass
        return []
    
    def collect_coverage(self, flush: bool = True) -> GoCoverageData:
        """
        Collect coverage data based on configured mode.
        
        Returns:
            GoCoverageData with coverage metrics
        """
        coverage = GoCoverageData()
        
        # Try real Go coverage first (if enabled)
        if self.coverage_mode in ('real', 'hybrid'):
            try:
                if self._copy_coverage_from_container():
                    real_coverage = self._parse_coverage_profiles()
                    if real_coverage.coverage_percentage > 0:
                        coverage = real_coverage
            except Exception as e:
                print(f"[GoCoverage] Real coverage error: {e}")
        
        # Add state-based metrics (always, for hybrid mode)
        state_coverage = self._get_state_based_coverage()
        
        if self.coverage_mode == 'hybrid' or coverage.coverage_percentage == 0:
            # Merge state-based coverage
            coverage = self._merge_coverage(coverage, state_coverage)
        
        # Add Authelia-specific metrics
        coverage.endpoint_coverage = dict(self.endpoint_hits)
        coverage.error_pattern_coverage = dict(self.error_patterns_seen)
        
        # Track maximum coverage - NEW
        if coverage.coverage_percentage > self.peak_coverage_percentage:
            self.peak_coverage_percentage = coverage.coverage_percentage
            self.max_coverage = GoCoverageData(
                instructions_covered=coverage.instructions_covered,
                instructions_total=coverage.instructions_total,
                lines_covered=coverage.lines_covered,
                lines_total=coverage.lines_total,
                coverage_percentage=coverage.coverage_percentage
            )
        
        self.history.append(coverage)
        return coverage
    
    def _merge_coverage(self, real: GoCoverageData, state: GoCoverageData) -> GoCoverageData:
        """Merge real and state-based coverage data."""
        merged = GoCoverageData()
        
        # Prefer real coverage if available
        if real.statements_total > 0:
            merged.statements_covered = real.statements_covered
            merged.statements_total = real.statements_total
            merged.packages_covered = real.packages_covered
            merged.packages_total = real.packages_total
            merged.package_coverage = real.package_coverage
            merged.hot_methods = real.hot_methods
        else:
            merged.statements_covered = state.statements_covered
            merged.statements_total = state.statements_total
        
        # Always include state-based metrics
        merged.module_coverage = {
            **state.module_coverage,
            **real.module_coverage
        }
        
        # Calculate combined coverage percentage
        real_weight = 0.7 if real.statements_total > 0 else 0.0
        state_weight = 1.0 - real_weight
        
        merged.coverage_percentage = (
            real.coverage_percentage * real_weight +
            state.coverage_percentage * state_weight
        )
        
        # Map to common fields
        merged.lines_covered = merged.statements_covered
        merged.lines_total = merged.statements_total
        merged.instructions_covered = merged.statements_covered
        merged.instructions_total = merged.statements_total
        
        return merged
    
    def _copy_coverage_from_container(self) -> bool:
        """Copy coverage profiles from Docker container to local directory"""
        try:
            # Snapshot control (CS revision 2026-09): each mid-run snapshot
            # docker-cp's the FULL in-container counter set, which reaches
            # GBs per snapshot with real -cover builds. Set
            # OAUTH_FUZZ_GO_SNAPSHOT=0 to disable mid-run snapshots; the
            # final counters still land in the GOCOVERDIR mount at graceful
            # container stop and are read from there.
            if os.environ.get('OAUTH_FUZZ_GO_SNAPSHOT', '1') == '0':
                return False
            # Check if container has coverage data
            result = subprocess.run(
                ['docker', 'exec', self.container_name, 'ls', '-la', self.container_coverage_dir],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                return False
            
            # Check for actual coverage files (covcounter* covmeta*)
            if 'covcounter' not in result.stdout and 'covmeta' not in result.stdout:
                return False
            
            # Create snapshot directory
            self.snapshot_count += 1
            snapshot_dir = os.path.join(self.coverage_dir, f'snapshot_{self.snapshot_count}')
            os.makedirs(snapshot_dir, exist_ok=True)
            
            # Copy coverage files from container
            subprocess.run(
                ['docker', 'cp', 
                 f'{self.container_name}:{self.container_coverage_dir}/.', 
                 snapshot_dir],
                capture_output=True, text=True, timeout=30
            )
            
            # Verify files were copied
            copied_files = os.listdir(snapshot_dir) if os.path.exists(snapshot_dir) else []
            return any('cov' in f for f in copied_files)
            
        except Exception as e:
            return False
    
    def _parse_coverage_profiles(self) -> GoCoverageData:
        """Parse Go coverage profiles using 'go tool covdata'."""
        coverage = GoCoverageData()
        
        try:
            # Find the most recent snapshot directory
            snapshots = sorted([
                d for d in os.listdir(self.coverage_dir) 
                if d.startswith('snapshot_')
            ])
            
            if not snapshots:
                return coverage
            
            latest_snapshot = os.path.join(self.coverage_dir, snapshots[-1])
            
            # Check if Go is available locally
            go_check = subprocess.run(['which', 'go'], capture_output=True)
            
            if go_check.returncode == 0:
                coverage = self._parse_with_go_tool(latest_snapshot)
            else:
                # Try using Docker with Go image
                coverage = self._parse_with_docker_go(latest_snapshot)
            
        except Exception as e:
            print(f"[GoCoverage] Parse error: {e}")
        
        return coverage
    
    def _parse_with_go_tool(self, coverage_dir: str) -> GoCoverageData:
        """Parse coverage using local Go installation"""
        coverage = GoCoverageData()
        
        try:
            # Get coverage percentage per package
            result = subprocess.run(
                ['go', 'tool', 'covdata', 'percent', '-i', coverage_dir],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                coverage = self._parse_covdata_output(result.stdout)
            
            # Get detailed function coverage
            func_result = subprocess.run(
                ['go', 'tool', 'covdata', 'func', '-i', coverage_dir],
                capture_output=True, text=True, timeout=60
            )
            
            if func_result.returncode == 0:
                self._parse_func_coverage(func_result.stdout, coverage)
                
        except subprocess.TimeoutExpired:
            print("[GoCoverage] Timeout parsing coverage")
        except Exception as e:
            print(f"[GoCoverage] Parse error: {e}")
        
        return coverage
    
    def _parse_with_docker_go(self, coverage_dir: str) -> GoCoverageData:
        """Parse coverage using Docker Go image when local Go unavailable"""
        coverage = GoCoverageData()
        
        try:
            result = subprocess.run([
                'docker', 'run', '--rm',
                '-v', f'{coverage_dir}:/coverage:ro',
                'golang:1.21-alpine',
                'go', 'tool', 'covdata', 'percent', '-i', '/coverage'
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                coverage = self._parse_covdata_output(result.stdout)
                
        except Exception as e:
            print(f"[GoCoverage] Docker parse error: {e}")
        
        return coverage
    
    def _parse_covdata_output(self, output: str) -> GoCoverageData:
        """Parse output from 'go tool covdata percent'."""
        coverage = GoCoverageData()
        total_statements = 0
        covered_statements = 0
        packages = []
        
        for line in output.strip().split('\n'):
            if 'coverage:' in line and 'of statements' in line:
                try:
                    parts = line.split('coverage:')
                    package_name = parts[0].strip()
                    pct_str = parts[1].split('%')[0].strip()
                    pct = float(pct_str)
                    
                    coverage.package_coverage[package_name] = pct
                    coverage.module_coverage[package_name] = pct
                    packages.append((package_name, pct))
                    
                    # Estimate statements per package
                    pkg_statements = 100
                    pkg_covered = int(pkg_statements * pct / 100)
                    
                    total_statements += pkg_statements
                    covered_statements += pkg_covered
                    
                except (ValueError, IndexError):
                    continue
        
        coverage.packages_total = len(packages)
        coverage.packages_covered = sum(1 for _, pct in packages if pct > 0)
        coverage.statements_total = total_statements
        coverage.statements_covered = covered_statements
        
        # Map to common coverage interface
        coverage.lines_total = total_statements
        coverage.lines_covered = covered_statements
        coverage.instructions_total = total_statements
        coverage.instructions_covered = covered_statements
        
        if total_statements > 0:
            coverage.coverage_percentage = (covered_statements / total_statements) * 100
        
        return coverage
    
    def _parse_func_coverage(self, output: str, coverage: GoCoverageData) -> None:
        """Parse output from 'go tool covdata func'."""
        methods_covered = 0
        methods_total = 0
        
        for line in output.strip().split('\n'):
            if '%' in line:
                methods_total += 1
                try:
                    pct_str = line.split()[-1].replace('%', '')
                    if float(pct_str) > 0:
                        methods_covered += 1
                        # Track hot methods
                        func_name = line.split(':')[-1].split()[0] if ':' in line else ''
                        if func_name:
                            coverage.hot_methods.add(func_name)
                except (ValueError, IndexError):
                    continue
        
        coverage.methods_total = methods_total
        coverage.methods_covered = methods_covered
    
    def _get_state_based_coverage(self) -> GoCoverageData:
        """
        Enhanced state-based coverage with security-weighted metrics.
        Uses response diversity, error patterns, endpoint coverage, and security path coverage.
        """
        coverage = GoCoverageData()
        
        # Multi-dimensional coverage calculation
        unique_state_count = len(self.unique_states)
        response_diversity = len(self.response_codes)
        endpoint_diversity = len(self.endpoint_hits)
        error_pattern_diversity = len(self.error_patterns_seen)
        interesting_count = len(self.interesting_cases)
        security_finding_count = len(self.security_findings)
        security_path_count = len(self.security_paths_covered)
        vuln_indicator_count = len(self.vulnerability_indicators)
        
        # Calculate endpoint coverage with importance weights
        weighted_endpoint_coverage = 0
        for endpoint, hits in self.endpoint_hits.items():
            weight = self._oauth_endpoint_weights.get(endpoint, 1.0)
            weighted_endpoint_coverage += min(hits, 10) * weight  # Cap at 10 hits per endpoint
        
        # Weighted coverage calculation with security focus
        coverage.instructions_covered = (
            unique_state_count * 3 +
            weighted_endpoint_coverage * 8 +  # Enhanced endpoint weight
            error_pattern_diversity * 5 +
            interesting_count * 8 +
            security_finding_count * 20 +  # Increased security finding weight
            security_path_count * 15 +     # New: security path bonus
            vuln_indicator_count * 25 +    # New: vulnerability indicator bonus
            response_diversity * 2
        )
        
        # FIXED: Use FIXED total based on estimated OAuth state space
        # NOT dependent on execution_count to prevent coverage decrease
        OAUTH_STATE_SPACE_ESTIMATE = 1000  # Fixed estimate for OAuth fuzzing
        SECURITY_PATH_ESTIMATE = 100       # Estimated security-relevant paths
        
        coverage.instructions_total = max(
            OAUTH_STATE_SPACE_ESTIMATE + SECURITY_PATH_ESTIMATE,
            coverage.instructions_covered + 100  # Always leave room for growth
        )
        
        coverage.lines_covered = coverage.instructions_covered
        coverage.lines_total = coverage.instructions_total
        coverage.statements_covered = coverage.instructions_covered
        coverage.statements_total = coverage.instructions_total
        
        if coverage.instructions_total > 0:
            coverage.coverage_percentage = min(100.0, 
                (coverage.instructions_covered / coverage.instructions_total) * 100)
        
        # Module coverage based on Authelia-specific dimensions
        coverage.module_coverage = {
            'state_exploration': min(100.0, unique_state_count * 5),
            'endpoint_coverage': min(100.0, endpoint_diversity * 15),
            'error_discovery': min(100.0, error_pattern_diversity * 10),
            'security_testing': min(100.0, security_finding_count * 25),
            'response_diversity': min(100.0, response_diversity * 8),
            'security_paths': min(100.0, security_path_count * 20),
            'vulnerability_indicators': min(100.0, vuln_indicator_count * 30),
        }
        
        return coverage
    
    def dump_coverage(self, port: int = None) -> bool:
        """Trigger coverage data collection snapshot."""
        # Check for crashes first
        self.check_for_crashes()
        
        coverage = self.collect_coverage(flush=True)
        return coverage is not None and coverage.coverage_percentage >= 0
    
    def generate_report(self, output_format: str = 'text') -> Optional[str]:
        """Generate comprehensive coverage report."""
        if not self.history:
            self.collect_coverage()
        
        if not self.history:
            return None
        
        latest = self.history[-1]
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        
        if output_format == 'json':
            report_path = os.path.join(self.report_dir, f'coverage_{timestamp}.json')
            report_data = {
                **latest.to_dict(),
                'state_metrics': {
                    'unique_states': len(self.unique_states),
                    'response_codes': sorted(self.response_codes),
                    'endpoint_hits': self.endpoint_hits,
                    'error_patterns': self.error_patterns_seen,
                    'security_findings': len(self.security_findings),
                    'crash_events': len(self.crash_events),
                    'total_executions': self.execution_count
                },
                'security_findings': self.security_findings[-20:],  # Last 20
                'crash_events': self.crash_events
            }
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)
            return report_path
        
        elif output_format == 'text':
            report_path = os.path.join(self.report_dir, f'coverage_{timestamp}.txt')
            with open(report_path, 'w') as f:
                f.write(f"Go Coverage Report - Authelia OAuth Fuzzing\n")
                f.write(f"Generated: {timestamp}\n")
                f.write("=" * 70 + "\n\n")
                
                f.write(f"Overall Coverage: {latest.coverage_percentage:.2f}%\n")
                f.write(f"Mode: {self.coverage_mode}\n\n")
                
                f.write("=== Code Coverage ===\n")
                f.write(f"Statements: {latest.statements_covered}/{latest.statements_total}\n")
                f.write(f"Packages: {latest.packages_covered}/{latest.packages_total}\n")
                f.write(f"Methods: {latest.methods_covered}/{latest.methods_total}\n\n")
                
                f.write("=== State-based Metrics ===\n")
                f.write(f"Unique states: {len(self.unique_states)}\n")
                f.write(f"Response codes: {sorted(self.response_codes)}\n")
                f.write(f"Endpoints hit: {len(self.endpoint_hits)}\n")
                f.write(f"Error patterns: {len(self.error_patterns_seen)}\n")
                f.write(f"Total executions: {self.execution_count}\n\n")
                
                f.write("=== Security Findings ===\n")
                f.write(f"Security-relevant findings: {len(self.security_findings)}\n")
                f.write(f"Crash events: {len(self.crash_events)}\n\n")
                
                if self.endpoint_hits:
                    f.write("=== Endpoint Coverage ===\n")
                    for endpoint, hits in sorted(self.endpoint_hits.items(), 
                                                 key=lambda x: -x[1]):
                        f.write(f"  {endpoint}: {hits} hits\n")
                    f.write("\n")
                
                if self.error_patterns_seen:
                    f.write("=== Error Patterns Discovered ===\n")
                    for pattern, count in sorted(self.error_patterns_seen.items(),
                                                  key=lambda x: -x[1]):
                        f.write(f"  {pattern}: {count} occurrences\n")
                    f.write("\n")
                
                if latest.package_coverage:
                    f.write("=== Package Coverage (Real) ===\n")
                    for pkg, pct in sorted(latest.package_coverage.items()):
                        f.write(f"  {pkg}: {pct:.1f}%\n")
                
            return report_path
        
        return None
    
    def parse_coverage_xml(self, xml_file: str = None):
        """Compatibility method - Go doesn't use XML, returns state-based coverage."""
        return self._get_state_based_coverage()
    
    def parse_granular_coverage_xml(self, xml_file: str = None):
        """Compatibility method - returns GoCoverageData."""
        return self._get_state_based_coverage()
    
    def set_classpaths(self, classpaths: List[str]) -> None:
        """Compatibility method - not applicable for Go."""
        pass
    
    def reset(self) -> None:
        """Reset coverage data for new fuzzing session."""
        self.history.clear()
        self.snapshot_count = 0
        self.baseline_coverage = None
        self.unique_states.clear()
        self.response_codes.clear()
        self.interesting_cases.clear()
        self.execution_count = 0
        self.endpoint_hits.clear()
        self.error_patterns_seen.clear()
        self.security_findings.clear()
        self.crash_events.clear()
        
        # Clear coverage profiles
        if os.path.exists(self.coverage_dir):
            shutil.rmtree(self.coverage_dir)
        os.makedirs(self.coverage_dir, exist_ok=True)
    
    def get_coverage_gain(self, baseline: GoCoverageData = None) -> float:
        """Calculate coverage gain from baseline."""
        if not self.history:
            return 0.0
        
        baseline = baseline or self.baseline_coverage
        if not baseline:
            return self.history[-1].coverage_percentage
        
        return self.history[-1].coverage_percentage - baseline.coverage_percentage
    
    def get_security_summary(self) -> Dict:
        """Get summary of security-relevant findings."""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in self.security_findings:
            sev = finding.get('severity', 'LOW')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            'total_findings': len(self.security_findings),
            'by_severity': severity_counts,
            'crash_count': len(self.crash_events),
            'unique_error_patterns': len(self.error_patterns_seen)
        }


class CoverageManagerFactory:
    """Factory to create appropriate coverage manager based on target type"""
    
    @staticmethod
    def create(config: Dict):
        """Create coverage manager based on target type."""
        target_type = config.get('target_type', 'keycloak').lower()
        
        if target_type in ('keycloak', 'java_based'):
            from core.coverage import JaCoCoManager
            jacoco_cfg = config.get('jacoco', {})
            return JaCoCoManager(
                work_dir=jacoco_cfg.get('work_dir', 'jacoco_tools'),
                version=jacoco_cfg.get('version')
            )
        
        elif target_type == 'authelia':
            coverage_dir = config.get('authelia', {}).get('coverage_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'authelia_service', 'coverage'))
            return GoCoverageManager(work_dir=coverage_dir)

        return None