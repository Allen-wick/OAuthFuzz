"""
Centralized path constants for the OAUTH_FUZZ project.

All modules should import PROJECT_ROOT from here instead of computing it
independently or hardcoding absolute paths.

Usage:
    from core.paths import PROJECT_ROOT, TARGETS_MANAGER_DIR
"""

import os

# Project root: two levels up from this file (core/paths.py -> project root)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Targets manager directory
TARGETS_MANAGER_DIR = os.path.join(PROJECT_ROOT, 'targets_manager')
