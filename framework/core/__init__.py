#!/usr/bin/env python3
"""
OAuth Fuzzing Framework - Core Module
Provides base abstractions for multi-target OAuth security testing.
"""

from core.config import OAuthConfig, FuzzerConfig, CoverageConfig, TargetConfig
from core.coverage import CoverageData, GranularCoverageData, JaCoCoManager
from core.adapters import BoofuzzAdapter, SeleniumSULAdapter
from core.security import SecurityOracles, RaceConditionTester
from core.health import ServerHealthMonitor
from core.fuzzer import AFLNetMinimalFuzzer
from core.generator import OAuthRequestGenerator, OAuthFuzzerWithCoverage

__all__ = [
    'OAuthConfig', 'FuzzerConfig', 'CoverageConfig', 'TargetConfig',
    'CoverageData', 'GranularCoverageData', 'JaCoCoManager',
    'BoofuzzAdapter', 'SeleniumSULAdapter',
    'SecurityOracles', 'RaceConditionTester',
    'ServerHealthMonitor',
    'AFLNetMinimalFuzzer',
    'OAuthRequestGenerator', 'OAuthFuzzerWithCoverage',
]