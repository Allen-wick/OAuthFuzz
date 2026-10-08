#!/usr/bin/env python3
"""
Complete OAuth Fuzzing with Coverage Integration
Supports multiple OAuth providers:
  - Keycloak       (Java, JaCoCo)
  - Authelia       (Go, Go native coverage)
  - Spring AS      (Java, JaCoCo)
  - Apache CXF     (Java, JaCoCo)
  - WSO2 IS        (Java, JaCoCo)
  - Authentik      (Python/Django, state-based coverage)
"""

import subprocess
import time
import json
import os
import sys
import argparse
import signal
import atexit

from core.generator import OAuthFuzzerWithCoverage
from core.fuzzer import OAuthFuzzMinimalFuzzer
AFLNetMinimalFuzzer = OAuthFuzzMinimalFuzzer  # backward compat alias
from core.adapters import BoofuzzAdapter, SeleniumSULAdapter
from OAuthMapper.OAuthProtocol import OAuthProtocol, OAuthConfig

# Target types that run on the JVM and support JaCoCo coverage.
JAVA_TARGETS = ('keycloak', 'java_based', 'spring_authz', 'cxf_oauth', 'wso2', 'shiro')
# Target types that use the GenericOIDC discovery-based dispatch path.
GENERIC_OIDC_TARGETS = ('spring_authz', 'cxf_oauth', 'wso2', 'logto')
# Target types that use Go native coverage (same pattern as Authelia).
GO_TARGETS = ('authelia', 'casdoor', 'ory_hydra', 'zitadel')
# Target types implemented in Python (state-based coverage via GoCoverageManager).
PYTHON_TARGETS = ('authentik', 'simplelogin')
# Target types implemented in Node.js (state-based coverage via GoCoverageManager).
NODE_TARGETS = ('nodeoidc', 'logto')
# All targets that use state-based coverage (Go native or response-pattern analysis).
STATE_BASED_TARGETS = GO_TARGETS + PYTHON_TARGETS + NODE_TARGETS

def _build_target_matcher(config: dict):
    """
    Build a predicate that tests whether a fully-qualified class or package
    name belongs to the currently-configured target, derived from the
    ``jacoco.includes`` filter. Returns a callable ``f(name) -> bool``.

    Example includes entry ``'org.springframework.security.oauth2.*'`` will
    match ``org/springframework/security/oauth2/...`` (JaCoCo exec format)
    as well as ``org.springframework.security.oauth2.*`` report package
    names.
    """
    includes = config.get('jacoco', {}).get('includes', []) or []
    prefixes = []
    for pat in includes:
        # Strip trailing wildcards, normalise both slash and dot separators
        stem = pat.rstrip('*').rstrip('.')
        if not stem:
            continue
        prefixes.append(stem.replace('.', '/'))
        prefixes.append(stem)  # dot form for report packages

    def matches(name: str) -> bool:
        if not name or not prefixes:
            return False
        n = name.replace('.', '/') if '.' in name else name
        for p in prefixes:
            pn = p.replace('.', '/')
            if n.startswith(pn):
                return True
        return False

    return matches

def get_target_manager(config: dict):
    """
    Factory function to get appropriate manager based on target type.

    Returns tuple: (manager_instance, realm_file_or_none, target_type)
    """
    target_type = config.get('target_type', 'keycloak').lower()

    if target_type in ('keycloak', 'java_based'):
        from targets_manager.keycloak_manager import KeycloakManager, create_test_realm
        manager = KeycloakManager(config)
        realm_file = create_test_realm()
        return manager, realm_file, 'keycloak'
    elif target_type == 'authelia':
        from targets_manager.authelia_manager import AutheliaManager
        manager = AutheliaManager(config)
        return manager, None, 'authelia'
    elif target_type == 'spring_authz':
        from targets_manager.spring_authz_manager import SpringAuthzManager
        manager = SpringAuthzManager(config)
        return manager, None, 'spring_authz'
    elif target_type == 'cxf_oauth':
        from targets_manager.cxf_oauth_manager import CxfOAuthManager
        manager = CxfOAuthManager(config)
        return manager, None, 'cxf_oauth'
    elif target_type == 'wso2':
        from targets_manager.wso2_manager import Wso2Manager
        manager = Wso2Manager(config)
        return manager, None, 'wso2'
    elif target_type == 'casdoor':
        from targets_manager.casdoor_manager import CasdoorManager
        manager = CasdoorManager(config)
        return manager, None, 'casdoor'
    elif target_type == 'ory_hydra':
        from targets_manager.ory_hydra_manager import OryHydraManager
        manager = OryHydraManager(config)
        return manager, None, 'ory_hydra'
    elif target_type == 'zitadel':
        from targets_manager.zitadel_manager import ZitadelManager
        manager = ZitadelManager(config)
        return manager, None, 'zitadel'
    elif target_type == 'shiro':
        from targets_manager.shiro_manager import ShiroTargetManager
        manager = ShiroTargetManager(config)
        return manager, None, 'shiro'
    elif target_type == 'authentik':
        from targets_manager.authentik_manager import AuthentikManager
        manager = AuthentikManager(config)
        return manager, None, 'authentik'
    elif target_type == 'simplelogin':
        from targets_manager.simplelogin_manager import SimpleLoginManager
        manager = SimpleLoginManager(config)
        return manager, None, 'simplelogin'
    elif target_type == 'nodeoidc':
        from targets_manager.nodeoidc_manager import NodeOIDCManager
        manager = NodeOIDCManager(config)
        return manager, None, 'nodeoidc'
    elif target_type == 'logto':
        from targets_manager.logto_manager import LogtoManager
        manager = LogtoManager(config)
        return manager, None, 'logto'
    else:
        raise ValueError(
            f"Unknown target_type: {target_type}. "
            f"Supported: keycloak, authelia, spring_authz, cxf_oauth, wso2, "
            f"casdoor, ory_hydra, zitadel, shiro, authentik, simplelogin, nodeoidc, logto"
        )


def check_dependencies(target_type: str = 'keycloak'):
    """Check if required dependencies are available"""
    print("Checking dependencies...")

    # Check Docker
    try:
        subprocess.run(['docker', '--version'], check=True, capture_output=True)
        print("✓ Docker is available")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("✗ Docker is not available")
        return False

    # Check Java (for all JVM-based targets with JaCoCo coverage)
    if target_type in JAVA_TARGETS:
        try:
            subprocess.run(['java', '-version'], check=True, capture_output=True)
            print("✓ Java is available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print(f"✗ Java is not available (required for {target_type}/JaCoCo)")
            return False
    elif target_type in STATE_BASED_TARGETS:
        runtime = 'Go' if target_type in GO_TARGETS else 'Python'
        print(f"○ Java not required for {target_type} target ({runtime})")

    # Check build tooling (SAS=Gradle, CXF=Maven; both bundle wrappers so host tool is fallback)
    if target_type == 'spring_authz':
        try:
            subprocess.run(['gradle', '-v'], check=True, capture_output=True)
            print("✓ Gradle is available (host)")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("⚠ Gradle not on PATH — SAS will use ./gradlew wrapper inside the source tree")
    elif target_type == 'cxf_oauth':
        try:
            subprocess.run(['mvn', '-version'], check=True, capture_output=True)
            print("✓ Maven is available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            print("⚠ Maven not on PATH — CXF build requires Maven, aborting")
            return False

    # Check Python packages
    try:
        import requests
        print("✓ requests is available")
    except ImportError:
        print("✗ requests is not available")
        return False

    # Check PyYAML (required for Authelia config generation)
    if target_type == 'authelia':
        try:
            import yaml
            print("✓ PyYAML is available")
        except ImportError:
            print("⚠ PyYAML not available (will use JSON fallback for Authelia)")

    return True


# Global reference for signal/atexit cleanup
_current_manager = None
_current_fuzzer = None
_current_config = None


def _signal_cleanup(signum, frame):
    """Signal handler: stop the current target manager on SIGTERM/SIGINT.

    Wall-clock-bounded campaigns end via SIGTERM; persist the session summary
    (fuzzing_summary.json + interesting_cases.jsonl) BEFORE teardown so the
    post-hoc replay corpus survives."""
    global _current_manager, _current_fuzzer, _current_config
    if _current_manager:
        print(f"\n[Signal {signum}] Saving session summary, then cleaning up target...", flush=True)
        if _current_fuzzer is not None and _current_config is not None:
            try:
                save_results_summary(_current_fuzzer, _current_config)
            except Exception as e:
                print(f"[Signal] summary save failed: {e}")
        try:
            _current_manager.stop()
        except Exception:
            pass
    sys.exit(1)


def _atexit_cleanup():
    """Atexit handler: stop the current target manager on process exit."""
    global _current_manager
    if _current_manager:
        try:
            _current_manager.stop()
        except Exception:
            pass


def run_fuzzing_session(config_file: str, iterations: int = 1000, mode: str = 'coverage',
                        adapter: str = 'none', config_overrides=None, fuzzer_class=None):
    """Run complete fuzzing session with multi-target support and enhanced security testing"""
    global _current_manager, _current_fuzzer, _current_config

    # Load configuration
    with open(config_file, 'r') as f:
        config = json.load(f)

    # P7: apply --set key=value overrides (dot-path, typed coercion)
    for _ov in (config_overrides or []):
        if '=' not in _ov:
            continue
        _key, _val = _ov.split('=', 1)
        _node = config
        _parts = _key.split('.')
        for _p in _parts[:-1]:
            _node = _node.setdefault(_p, {})
        if _val.lower() in ('true', 'false'):
            _node[_parts[-1]] = (_val.lower() == 'true')
        else:
            try:
                _node[_parts[-1]] = int(_val)
            except ValueError:
                try:
                    _node[_parts[-1]] = float(_val)
                except ValueError:
                    _node[_parts[-1]] = _val
        print(f"[P7] config override {_key} = {_node[_parts[-1]]!r}")

    # Deterministic per-run seed for multi-trial campaigns (fuzzing.seed).
    # Applied after --set overrides so it participates in the same mechanism.
    _run_seed = config.get('fuzzing', {}).get('seed')
    if _run_seed is not None:
        import random as _random_mod
        _random_mod.seed(int(_run_seed))
        print(f"[seed] random seed = {int(_run_seed)}")

    target_type = config.get('target_type', 'keycloak').lower()

    # Determine coverage type
    if target_type in PYTHON_TARGETS:
        coverage_type = 'State-based'
    elif target_type in GO_TARGETS:
        coverage_type = 'Go/State-based'
    elif target_type in JAVA_TARGETS:
        coverage_type = 'JaCoCo'
    else:
        coverage_type = 'JaCoCo'

    print(f"=== OAuth Fuzzing with {coverage_type} Coverage ===")
    print(f"Target: {target_type.upper()}")
    print(f"Mode: {mode}")
    print(f"Adapter: {adapter}")
    print(f"Iterations: {iterations}")
    print("=" * 60)

    # Get appropriate manager
    manager, realm_file, actual_target = get_target_manager(config)

    # Get coverage manager
    coverage_manager = None
    if actual_target in JAVA_TARGETS:
        coverage_manager = manager.jacoco
    elif actual_target in STATE_BASED_TARGETS and hasattr(manager, 'go_coverage'):
        coverage_manager = manager.go_coverage

    # Track session statistics
    session_stats = {
        'start_time': time.time(),
        'target': actual_target,
        'mode': mode,
        'adapter': adapter,
        'iterations_requested': iterations,
        'security_findings': [],
        'coverage_snapshots': [],
        'crashes_detected': 0,
    }

    try:
        # Step 1: Create test configuration
        if realm_file:
            print("\n1. Creating test realm...")
            print(f"Created valid realm configuration: {realm_file}")
        else:
            print(f"\n1. Using file-based configuration ({actual_target})...")

        # Step 2: Start OAuth provider
        print(f"\n2. Starting {actual_target.capitalize()}...")
        if not manager.start():
            print(f"Failed to start {actual_target.capitalize()}")
            if hasattr(manager, 'get_recent_logs'):
                print(manager.get_recent_logs(tail=200))
            return False

        # Register cleanup so containers are removed even on crash/kill
        manager.register_cleanup()
        _current_manager = manager
        signal.signal(signal.SIGTERM, _signal_cleanup)
        atexit.register(_atexit_cleanup)

        # Step 3: Import realm/configuration
        print("\n3. Importing configuration...")
        if realm_file:
            if not manager.import_config(realm_file):
                print("Failed to import realm")
                return False
        else:
            manager.import_config()

        # Step 4: Wait for provider to be fully ready
        print(f"\n4. Waiting for {actual_target.capitalize()} to be fully ready...")
        # Authelia/Go boots quickly; Java stacks (esp. WSO2) need more.
        if actual_target == 'authentik':
            time.sleep(15)  # Multi-container (PG+Redis+server+worker)
        elif actual_target == 'simplelogin':
            time.sleep(10)  # Multi-container (PG+web+job-runner)
        elif actual_target in GO_TARGETS:
            time.sleep(5)
        elif actual_target == 'wso2':
            time.sleep(20)
        else:
            time.sleep(10)

        # Step 5: Run fuzzing
        print("\n5. Starting OAuth fuzzing with feedback...")

        # Inject manager reference
        if target_type in STATE_BASED_TARGETS:
            config['_authelia_manager'] = manager  # keeps backward compat name
        elif target_type in GENERIC_OIDC_TARGETS or target_type == 'shiro':
            config['_target_manager'] = manager
        else:
            config['_kc_manager'] = manager
        jacoco_manager = manager.jacoco if actual_target in JAVA_TARGETS else None

        fuzzer = None
        if mode == 'coverage':
            fuzzer = OAuthFuzzerWithCoverage(config, jacoco_manager=jacoco_manager)

            # Inject state-based coverage manager for non-Java targets
            if actual_target in STATE_BASED_TARGETS and coverage_manager:
                fuzzer.go_coverage = coverage_manager

            # (globals declared once at function top)
            _current_fuzzer, _current_config = fuzzer, config
            fuzzer.fuzz(iterations)

        elif mode == 'aflnet':
            bf = BoofuzzAdapter(config.get('oauth', {})) if adapter in ('boofuzz', 'both') else None
            sel = SeleniumSULAdapter(config.get('oauth', {})) if adapter in ('selenium', 'both') else None
            fuzz_cls = AFLNetMinimalFuzzer
            if fuzzer_class:
                _mod, _, _cls = fuzzer_class.partition(':')
                import importlib
                fuzz_cls = getattr(importlib.import_module(_mod), _cls)
                print(f"[P7] fuzzer class: {fuzzer_class}")
            fuzzer = fuzz_cls(config, jacoco_manager=jacoco_manager,
                              boofuzz_adapter=bf, selenium_adapter=sel)

            # Inject state-based coverage for non-Java targets in OAuthFuzz mode
            if actual_target in STATE_BASED_TARGETS and coverage_manager:
                fuzzer.go_coverage = coverage_manager

            # (global declared once in the coverage branch above — scope-wide)
            _current_fuzzer, _current_config = fuzzer, config
            fuzzer.fuzz(iterations)

        elif mode == 'auth-test':
            return _run_auth_test(config, manager, actual_target)

        elif mode == 'security-scan':
            # NEW: Dedicated security scanning mode
            return _run_security_scan(config, manager, actual_target, coverage_manager, iterations)

        else:
            print(f"Unknown mode: {mode}")
            return False

        # Step 6: Generate final coverage report
        print("\n6. Generating final report...")
        try:
            if actual_target in JAVA_TARGETS and jacoco_manager:
                try:
                    jacoco_manager.dump_coverage(port=config.get('jacoco', {}).get('agent_port', 6300))
                except Exception as _e:
                    print(f"[Final] dump failed: {_e}")

            # Stop the target
            manager.stop()

            if actual_target in JAVA_TARGETS and jacoco_manager:
                jacoco_manager.generate_report()
            elif actual_target in STATE_BASED_TARGETS and coverage_manager:
                coverage_manager.generate_report(output_format='json')
                coverage_manager.generate_report(output_format='text')
        except Exception:
            pass

        # Step 7: Save fuzzing results summary
        if fuzzer:
            save_results_summary(fuzzer, config)

            # Generate security findings report
            if actual_target in STATE_BASED_TARGETS and coverage_manager:
                _generate_security_report(coverage_manager, config)

        return True

    except KeyboardInterrupt:
        print("\n\nFuzzing interrupted by user")
        return False
    except Exception as e:
        print(f"\nFuzzing error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        print("\nCleaning up...")
        try:
            manager.stop()
        except Exception:
            pass

        if realm_file and os.path.exists(realm_file):
            try:
                os.remove(realm_file)
            except Exception:
                pass


def _run_security_scan(config: dict, manager, target_type: str, coverage_manager, iterations: int) -> bool:
    """Dedicated security-focused scanning mode"""
    print("\n=== Running Security-Focused Scan ===")
    
    # Configure for security testing
    config['fuzzing'] = config.get('fuzzing', {})
    config['fuzzing']['security_mode'] = True
    config['fuzzing']['canonicalize_sequences'] = False  # Allow more random sequences
    
    # Use BoofuzzAdapter with OAuth-specific attacks
    bf = BoofuzzAdapter(config.get('oauth', {}))
    
    # Inject manager reference
    if target_type in STATE_BASED_TARGETS:
        config['_authelia_manager'] = manager
    elif target_type in GENERIC_OIDC_TARGETS:
        config['_target_manager'] = manager
    else:
        config['_kc_manager'] = manager
    
    fuzzer = AFLNetMinimalFuzzer(config, boofuzz_adapter=bf)
    
    # Inject coverage manager
    if target_type in STATE_BASED_TARGETS and coverage_manager:
        fuzzer.go_coverage = coverage_manager
    
    # Run with security focus
    fuzzer.fuzz(iterations)
    
    # Generate security report
    security_summary = {
        'scan_type': 'security',
        'target': target_type,
        'iterations': iterations,
        'findings': fuzzer.interesting_cases,
        'total_executions': fuzzer.execution_count,
    }
    
    if coverage_manager:
        security_summary['security_findings'] = coverage_manager.security_findings
        security_summary['vulnerability_indicators'] = getattr(coverage_manager, 'vulnerability_indicators', [])
    
    # Save security scan results
    output_dir = config.get('output_dir', 'out/security_scan')
    os.makedirs(output_dir, exist_ok=True)
    
    scan_report_path = os.path.join(output_dir, f'security_scan_{int(time.time())}.json')
    with open(scan_report_path, 'w') as f:
        json.dump(security_summary, f, indent=2, default=str)
    
    print(f"\nSecurity scan report saved: {scan_report_path}")
    
    # Print summary
    print("\n=== Security Scan Summary ===")
    if coverage_manager:
        findings = coverage_manager.security_findings
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            sev = f.get('severity', 'LOW')
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        print(f"Total security findings: {len(findings)}")
        print(f"  CRITICAL: {severity_counts['CRITICAL']}")
        print(f"  HIGH: {severity_counts['HIGH']}")
        print(f"  MEDIUM: {severity_counts['MEDIUM']}")
        print(f"  LOW: {severity_counts['LOW']}")
    
    return True


def _generate_security_report(coverage_manager, config: dict) -> None:
    """Generate detailed security findings report"""
    output_dir = config.get('output_dir', 'out/oauth_coverage')
    os.makedirs(output_dir, exist_ok=True)
    
    security_report = {
        'timestamp': time.time(),
        'target_type': config.get('target_type', 'unknown'),
        'total_findings': len(coverage_manager.security_findings),
        'crash_events': coverage_manager.crash_events,
        'vulnerability_indicators': getattr(coverage_manager, 'vulnerability_indicators', []),
        'findings_by_severity': {},
        'findings_by_endpoint': {},
        'detailed_findings': coverage_manager.security_findings[-100:],  # Last 100
    }
    
    # Group by severity
    for finding in coverage_manager.security_findings:
        sev = finding.get('severity', 'UNKNOWN')
        if sev not in security_report['findings_by_severity']:
            security_report['findings_by_severity'][sev] = []
        security_report['findings_by_severity'][sev].append(finding)
    
    # Group by endpoint
    for finding in coverage_manager.security_findings:
        endpoint = finding.get('endpoint', 'unknown')
        if endpoint not in security_report['findings_by_endpoint']:
            security_report['findings_by_endpoint'][endpoint] = []
        security_report['findings_by_endpoint'][endpoint].append(finding)
    
    report_path = os.path.join(output_dir, 'security_findings.json')
    with open(report_path, 'w') as f:
        json.dump(security_report, f, indent=2, default=str)
    
    print(f"Security findings report saved: {report_path}")


def _run_auth_test(config: dict, manager, target_type: str) -> bool:
    """Run minimal OAuth authorization code test"""
    print("\n=== Running minimal OAuth Authorization Code test ===")
    
    oc = config.get('oauth', {})
    
    if target_type == 'java_based':
        target_type = 'keycloak'
    
    base_url = oc.get('base_url', 'http://127.0.0.1:8080')
    realm = oc.get('realm', 'fuzz') if target_type == 'keycloak' else ''
    
    oauth_conf = OAuthConfig(
        base_url=base_url,
        realm=realm,
        client_id=oc.get('client_id', 'fuzz-client'),
        client_secret=oc.get('client_secret', 'fuzz-client-secret'),
        redirect_uri=oc.get('redirect_uri', 'http://127.0.0.1:7777/callback'),
        username=oc.get('user', 'testuser'),
        password=oc.get('password', 'testpass'),
        scope=oc.get('scope', 'openid profile email'),
        target_type=target_type
    )
    
    proto = OAuthProtocol(oauth_conf)

    if target_type == 'authentik':
        authentik_cfg = config.get('authentik', {})
        proto.config._authentik_app_slug = authentik_cfg.get('app_slug', 'fuzz-app')
    elif target_type == 'authelia':
        proto.session.verify = oc.get('verify_ssl', False)
    
    try:
        rt, r1 = proto.authorize()
        print(f"Authorize -> {r1.status_code}, login_form_url={proto.login_form_url}")
    except Exception as e:
        print(f"Authorize -> FAILED: {e}")
        print("\n=== Minimal auth-code test completed ===")
        return False
    
    try:
        rt, r2 = proto.login()
        print(f"Login -> {r2.status_code}")
        if r2.status_code == 401:
            try:
                body = r2.json()
                print(f"  Login error: {body.get('message', body.get('status', 'Unknown'))}")
            except Exception:
                pass
    except Exception as e:
        print(f"Login -> FAILED: {e}")
        print("\n=== Minimal auth-code test completed ===")
        return False
    
    try:
        result = proto.auth_code_redirect()
        if result is None:
            print(f"AuthCodeRedirect -> SKIPPED (not implemented for {target_type})")
            r3_status = None
        else:
            rt, r3 = result
            r3_status = r3.status_code
            print(f"AuthCodeRedirect -> {r3_status}, auth_code={proto.auth_code}")
    except Exception as e:
        print(f"AuthCodeRedirect -> FAILED: {e}")
        r3_status = None
    
    try:
        rt, r4 = proto.token_exchange()
        print(f"TokenExchange -> {r4.status_code}, access_token_present={bool(proto.access_token)}")
        if r4.status_code >= 400:
            # Surface the server's actual error body so the next iteration
            # does not require a docker-logs round-trip.
            body_preview = (r4.text or '')[:600].replace('\n', ' ')
            print(f"  TokenExchange body: {body_preview}")
    except Exception as e:
        print(f"TokenExchange -> FAILED: {e}")
        print("\n=== Minimal auth-code test completed ===")
        return False
    
    ok = proto.auth_code is not None and r4.status_code == 200 and bool(proto.access_token)
    
    if not ok:
        # Dump the last 120 lines of the container log BEFORE manager.stop()
        # removes the container.  Essential for debugging CXF/SAS/WSO2
        # 500s where the exception is only on Tomcat's stderr.
        try:
            container_name = getattr(manager, 'container_name', None)
            if container_name:
                out = subprocess.run(
                    ['docker', 'logs', '--tail', '120', container_name],
                    capture_output=True, text=True, timeout=10)
                tail = (out.stdout or '') + (out.stderr or '')
                # Show ALL lines containing error indicators, not just
                # stack-trace keywords.  The real cause may be logged at
                # WARN or ERROR level without a full stack trace.
                interesting = [ln for ln in tail.splitlines()
                               if any(k in ln.lower() for k in
                                      ('exception', 'severe', 'error',
                                       'caused by', 'at org.',
                                       'at javax.', 'fail', 'unable',
                                       'invalid', 'denied', 'forbidden',
                                       'no message body'))]
                if interesting:
                    print("\n--- Container stack trace (pre-cleanup) ---")
                    for ln in interesting[-60:]:
                        print(f"  {ln}")
                    print("-------------------------------------------")
                else:
                    # No filtered matches — dump last 40 lines raw
                    print("\n--- Container logs (pre-cleanup, raw tail) ---")
                    for ln in tail.splitlines()[-40:]:
                        print(f"  {ln}")
                    print("-------------------------------------------")
        except Exception:
            pass

    print(f"\n=== Minimal auth-code test completed {'✓' if ok else '✗'} ===")
    return bool(ok)


def _print_startup_logs(manager):
    """Print startup failure logs"""
    try:
        container_name = getattr(manager, 'container_name', 'unknown')
        out = subprocess.run(
            ['docker', 'logs', '--tail', '200', container_name],
            check=True, capture_output=True, text=True
        )
        print("=== Container logs on startup failure ===")
        print(out.stdout)
    except Exception as e:
        print(f"[Startup logs fetch failed]: {e}")


def run_diagnostic(config_file: str, target_type: str = 'auto', verbose: bool = False, start_if_needed: bool = False):
    """
    Run coverage collection diagnostics for the specified target.
    Checks JaCoCo agent connectivity, exec data integrity, classpath
    alignment, and coverage report validity. Can optionally start the
    target container if it's not running.

    Usage:
      python3 run_oauth_fuzzing.py --target spring_authz --config configs/oauth_spring_authz.json --mode diagnose
      python3 run_oauth_fuzzing.py --target wso2 --config configs/oauth_wso2.json --mode diagnose --verbose
      python3 run_oauth_fuzzing.py --target cxf_oauth --config configs/oauth_cxf.json --mode diagnose --start
    """
    import re
    import socket

    # Load configuration
    with open(config_file, 'r') as f:
        config = json.load(f)

    if target_type == 'auto':
        target_type = config.get('target_type', 'keycloak').lower()
        if target_type == 'java_based':
            target_type = 'keycloak'

    print(f"\n{'='*60}")
    print(f"  Coverage Collection Diagnostic")
    print(f"  Target: {target_type.upper()}")
    print(f"{'='*60}\n")

    results = {
        'target_type': target_type,
        'timestamp': time.time(),
        'checks': {},
        'issues': [],
        'recommendations': [],
    }

    # ─── Check 1: Container Running ───
    print("[1/8] Checking container status...")
    manager, realm_file, actual_target = get_target_manager(config)
    container_name = getattr(manager, 'container_name', 'unknown')
    is_healthy = manager.is_healthy()

    # ─── Auto-start if needed ───
    if not is_healthy and start_if_needed:
        print(f"  Container not running. Auto-starting {actual_target}...")
        ok = manager.start()

        if ok:
            # Give server a moment to stabilize after startup
            time.sleep(2)
            is_healthy = manager.is_healthy()
            if not is_healthy:
                # Retry a few times
                for _ in range(3):
                    time.sleep(2)
                    is_healthy = manager.is_healthy()
                    if is_healthy:
                        break
            if is_healthy:
                print(f"  ✓ {actual_target} started successfully")
            else:
                print(f"  ⚠ {actual_target} started (start() returned True) but is_healthy() still failing")
                print(f"    Continuing diagnostic with container access via Docker...")
                is_healthy = True
        else:
            print(f"  ✗ Failed to start {actual_target}")

    results['checks']['container_running'] = is_healthy
    if is_healthy:
        print(f"  ✓ Container '{container_name}' is running and healthy")
    else:
        print(f"  ✗ Container '{container_name}' is NOT accessible")
        results['issues'].append('CONTAINER_NOT_RUNNING')
        if not start_if_needed:
            results['recommendations'].append(
                f"Start the target first, or use --start flag: "
                f"python3 run_oauth_fuzzing.py --target {target_type} "
                f"--config {config_file} --mode diagnose --start"
            )

    # ─── Check 2: JaCoCo Agent Port Reachable ───
    print("\n[2/8] Checking JaCoCo agent port...")
    if target_type in STATE_BASED_TARGETS:
        print(f"  ○ Skipped ({target_type} uses state-based coverage, not JaCoCo)")
        results['checks']['jacoco_agent'] = 'N/A'
    else:
        agent_port = config.get('jacoco', {}).get('agent_port', 6300)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(('127.0.0.1', agent_port))
            s.close()
            results['checks']['jacoco_agent_reachable'] = True
            print(f"  ✓ JaCoCo agent is listening on port {agent_port}")
        except Exception as e:
            results['checks']['jacoco_agent_reachable'] = False
            results['checks']['jacoco_agent_error'] = str(e)
            print(f"  ✗ JaCoCo agent NOT reachable on port {agent_port}: {e}")
            results['issues'].append('JACOCO_AGENT_NOT_REACHABLE')
            results['recommendations'].append(
                "Verify the -javaagent argument was passed correctly to the JVM. "
                "Check for shell glob expansion issues with includes=* patterns."
            )

    # ─── Check 3: JVM Command Line Contains Agent ───
    print("\n[3/8] Checking JVM command line for JaCoCo agent...")
    if target_type in STATE_BASED_TARGETS:
        print("  ○ Skipped (not applicable for non-Java target)")
    elif is_healthy:
        try:
            cmd_result = subprocess.run(
                ['docker', 'exec', container_name,
                 'sh', '-c', 'cat /proc/1/cmdline | tr "\\0" " "'],
                capture_output=True, text=True, timeout=5
            )
            cmdline = cmd_result.stdout
            has_agent = 'jacocoagent' in cmdline
            results['checks']['jvm_has_jacoco_agent'] = has_agent

            if has_agent:
                print(f"  ✓ JaCoCo agent found in JVM command line")
            else:
                print(f"  ✗ JaCoCo agent NOT found in JVM command line")
                results['issues'].append('JACOCO_AGENT_NOT_IN_CMDLINE')
                results['recommendations'].append(
                    "The JVM was started without the -javaagent argument. "
                    "Check the container entrypoint and jvm.args file."
                )

            # Check includes pattern
            has_includes = 'includes=' in cmdline
            results['checks']['jvm_has_includes'] = has_includes
            if has_includes:
                inc_match = re.search(r'includes=([^,\s]+)', cmdline)
                if inc_match:
                    includes_val = inc_match.group(1)
                    includes_list = includes_val.split(':')
                    print(f"  ✓ JaCoCo includes filter found: {', '.join(includes_list)}")
                    results['checks']['jacoco_includes_value'] = includes_val
                else:
                    print(f"  ⚠ JaCoCo includes filter present but could not extract value")
            else:
                print(f"  ✗ JaCoCo includes filter NOT found (will instrument ALL classes)")
                results['issues'].append('JACOCO_NO_INCLUDES_FILTER')

            # Check for set -f in entrypoint
            try:
                ep_result = subprocess.run(
                    ['docker', 'exec', container_name, 'cat', '/config/entrypoint.sh'],
                    capture_output=True, text=True, timeout=5
                )
                if ep_result.returncode == 0 and 'set -f' in ep_result.stdout:
                    print(f"  ✓ entrypoint.sh has 'set -f' (glob protection enabled)")
                    results['checks']['entrypoint_has_set_f'] = True
                elif ep_result.returncode == 0:
                    print(f"  ✗ entrypoint.sh missing 'set -f' (glob expansion NOT protected!)")
                    results['checks']['entrypoint_has_set_f'] = False
                    results['issues'].append('ENTRYPOINT_MISSING_SET_F')
                    results['recommendations'].append(
                        "Add 'set -f' to entrypoint.sh to prevent shell glob expansion "
                        "from corrupting JaCoCo includes=* patterns."
                    )
            except Exception:
                pass

            if verbose:
                print(f"  [verbose] CMDLINE: {cmdline[:300]}...")
        except Exception as e:
            results['checks']['jvm_cmdline_error'] = str(e)
            print(f"  ✗ Cannot inspect JVM command line: {e}")
    else:
        print("  ○ Skipped (container not running)")

    # ─── Check 4: Entrypoint Configuration ───
    print("\n[4/8] Checking container entrypoint...")
    if target_type in STATE_BASED_TARGETS:
        print("  ○ Skipped")
    elif is_healthy:
        try:
            entry_result = subprocess.run(
                ['docker', 'inspect', container_name,
                 '--format', '{{.Config.Entrypoint}}'],
                capture_output=True, text=True, timeout=5
            )
            entrypoint = entry_result.stdout.strip()
            results['checks']['container_entrypoint'] = entrypoint

            if entrypoint.startswith('/config/entrypoint.sh') or '/config/entrypoint.sh' in entrypoint:
                print(f"  ✓ Using safe entrypoint.sh (avoids shell glob issues)")
                results['checks']['uses_safe_entrypoint'] = True
            elif 'sh' in entrypoint.lower() or '/bin/sh' in entrypoint.lower():
                print(f"  ⚠ Using shell-based entrypoint: {entrypoint}")
                print(f"     Shell expansion may corrupt JaCoCo includes=* patterns")
                results['checks']['uses_safe_entrypoint'] = False
                results['issues'].append('UNSAFE_SHELL_ENTRYPOINT')
                results['recommendations'].append(
                    "Use the file-based entrypoint.sh pattern (see keycloak_manager.py) "
                    "to avoid shell glob expansion of JaCoCo includes patterns."
                )
            else:
                print(f"  ℹ Entrypoint: {entrypoint}")
                results['checks']['uses_safe_entrypoint'] = None
        except Exception as e:
            print(f"  ✗ Cannot inspect entrypoint: {e}")

        # Check jvm.args inside container
        try:
            args_result = subprocess.run(
                ['docker', 'exec', container_name, 'cat', '/config/jvm.args'],
                capture_output=True, text=True, timeout=5
            )
            if args_result.returncode == 0:
                jvm_args_content = args_result.stdout
                results['checks']['jvm_args_content'] = jvm_args_content[:500]
                if verbose:
                    print(f"  [verbose] jvm.args:")
                    for line in jvm_args_content.splitlines():
                        print(f"    {line}")
                if '-javaagent:' in jvm_args_content:
                    print(f"  ✓ jvm.args contains -javaagent argument")
                else:
                    print(f"  ✗ jvm.args missing -javaagent argument!")
                    results['issues'].append('JVM_ARGS_MISSING_JAVAAGENT')
        except Exception:
            pass
    else:
        print("  ○ Skipped (container not running)")

    # ─── Check 5: JaCoCo Exec Data Integrity ───
    print("\n[5/9] Checking JaCoCo exec data...")
    if target_type in STATE_BASED_TARGETS:
        print("  ○ Skipped (state-based coverage target)")
    else:
        jacoco_manager = getattr(manager, 'jacoco', None)
        if jacoco_manager:
            try:
                agent_port = config.get('jacoco', {}).get('agent_port', 6300)
                dump_ok = jacoco_manager.dump_coverage(port=agent_port)
                results['checks']['jacoco_dump_ok'] = dump_ok

                exec_path = os.path.join(jacoco_manager.work_dir, 'coverage.exec')
                if os.path.exists(exec_path):
                    exec_size = os.path.getsize(exec_path)
                    results['checks']['exec_file_size'] = exec_size
                    results['checks']['exec_file_path'] = exec_path

                    if exec_size > 50000:
                        print(f"  ✓ Exec file size: {exec_size:,} bytes (contains probe data)")
                        results['checks']['exec_has_probe_data'] = True
                    elif exec_size > 1000:
                        print(f"  ⚠ Exec file size: {exec_size:,} bytes (may have limited probe data)")
                        results['checks']['exec_has_probe_data'] = 'partial'
                    else:
                        print(f"  ✗ Exec file size: {exec_size:,} bytes (NO probe data!)")
                        results['checks']['exec_has_probe_data'] = False
                        results['issues'].append('EXEC_NO_PROBE_DATA')
                else:
                    print(f"  ✗ Exec file not found at: {exec_path}")
                    results['checks']['exec_file_exists'] = False
                    results['issues'].append('EXEC_FILE_NOT_FOUND')

                if not dump_ok:
                    print(f"  ✗ JaCoCo dump_coverage() returned False")
                    results['issues'].append('JACOCO_DUMP_FAILED')
            except Exception as e:
                print(f"  ✗ JaCoCo dump failed: {e}")
                results['checks']['jacoco_dump_error'] = str(e)
                results['issues'].append('JACOCO_DUMP_EXCEPTION')
        else:
            print(f"  ✗ JaCoCo manager not available")
            results['issues'].append('JACOCO_MANAGER_NOT_AVAILABLE')

    # ─── Check 5b: Exec Data Analysis (execinfo) ───
    print("\n[5b/9] Analyzing exec data contents...")
    if target_type in STATE_BASED_TARGETS:
        print("  ○ Skipped (state-based coverage target)")
    elif jacoco_manager:
        try:
            exec_info = jacoco_manager.exec_info()
            if exec_info:
                class_count = exec_info.get('class_count', 0)
                class_ids = exec_info.get('class_ids', {})
                results['checks']['exec_class_count'] = class_count

                if class_count > 0:
                    print(f"  ✓ Exec file contains data for {class_count} classes")
                    # Show first few class names to verify they're the right classes
                    sample_classes = list(class_ids.keys())[:10]
                    matches_target = _build_target_matcher(config)
                    target_classes = [c for c in class_ids.keys() if matches_target(c)]
                    results['checks']['exec_target_classes'] = len(target_classes)
                    results['checks']['exec_sample_classes'] = sample_classes

                    if target_classes:
                        print(f"  ✓ Found {len(target_classes)} target classes in exec data:")
                        for tc in target_classes[:10]:
                            print(f"    - {tc}")
                        if len(target_classes) > 10:
                            print(f"    ... and {len(target_classes) - 10} more")
                    else:
                        print(f"  ✗ No target classes in exec data!")
                        print(f"    (Expected package prefixes from config.jacoco.includes)")
                        print(f"    Classes found in exec: {sample_classes[:5]}")
                        results['issues'].append('EXEC_NO_TARGET_CLASSES')
                        results['recommendations'].append(
                            "The exec file contains probe data but NOT for the target classes. "
                            "The JaCoCo includes filter may not be matching at runtime. "
                            "Check if shell expansion corrupted the includes pattern."
                        )

                    if verbose:
                        print(f"  [verbose] All classes in exec ({class_count}):")
                        for name in sorted(class_ids.keys()):
                            print(f"    {class_ids[name]} {name}")
                else:
                    print(f"  ✗ Exec file contains NO class data")
                    results['issues'].append('EXEC_EMPTY_CLASS_DATA')

                # Show raw execinfo output snippet
                raw = exec_info.get('raw_output', '')
                if raw and verbose:
                    print(f"  [verbose] execinfo output (first 1000 chars):")
                    for line in raw[:1000].splitlines():
                        print(f"    {line}")
            else:
                print(f"  ⚠ execinfo analysis not available (CLI may not support this command)")
        except Exception as e:
            print(f"  ✗ Exec analysis failed: {e}")

    # ─── Check 6: Classpath Alignment ───
    print("\n[6/8] Checking classpath alignment...")
    if target_type in STATE_BASED_TARGETS:
        print("  ○ Skipped (state-based coverage target)")
    elif jacoco_manager:
        # Auto-prepare classpaths if the manager supports it (SAS / CXF / WSO2 /
        # any future Spring-Boot-fat-JAR target can implement ensure_classpaths_ready).
        if hasattr(manager, 'ensure_classpaths_ready'):
            cp_ok = manager.ensure_classpaths_ready()
            if cp_ok:
                print(f"  ✓ Classpaths prepared via ensure_classpaths_ready()")

        classpaths = getattr(jacoco_manager, 'classpaths', [])
        results['checks']['classpath_count'] = len(classpaths)
        print(f"  Classpaths configured: {len(classpaths)}")

        if len(classpaths) == 0:
            print(f"  ✗ No classpaths configured! JaCoCo report cannot match classes")
            results['issues'].append('NO_CLASSPATHS')
            results['recommendations'].append(
                "Run _prepare_classpaths() on the target manager after the container starts. "
                "This extracts application classes from the Spring Boot fat JAR (SAS) "
                "or the exploded WEB-INF/classes (CXF/WSO2)."
            )
        else:
            # Verify each classpath exists
            valid_count = 0
            missing_count = 0
            for cp in classpaths:
                if os.path.exists(cp):
                    valid_count += 1
                else:
                    missing_count += 1
                    if verbose:
                        print(f"  [verbose] MISSING classpath: {cp}")

            results['checks']['valid_classpaths'] = valid_count
            results['checks']['missing_classpaths'] = missing_count

            if missing_count > 0:
                print(f"  ⚠ {missing_count}/{len(classpaths)} classpaths DO NOT exist on disk")
                results['issues'].append('MISSING_CLASSPATHS')
            else:
                print(f"  ✓ All {valid_count} classpaths exist on disk")

            # Check if application classes dir is present (critical for Spring Boot)
            classes_dir_present = any(
                'classes' in cp and os.path.isdir(cp) for cp in classpaths
            )
            results['checks']['has_application_classes_dir'] = classes_dir_present
            if classes_dir_present:
                # Count .class files in the classes dir
                for cp in classpaths:
                    if 'classes' in cp and os.path.isdir(cp):
                        class_count = sum(
                            1 for root, dirs, files in os.walk(cp)
                            for f in files if f.endswith('.class')
                        )
                        print(f"  ✓ Application classes dir: {cp} ({class_count} .class files)")
                        results['checks']['application_class_count'] = class_count
                        if class_count == 0:
                            print(f"  ✗ Classes directory exists but has 0 .class files!")
                            results['issues'].append('EMPTY_CLASSES_DIR')
                            results['recommendations'].append(
                                "The BOOT-INF/classes/ extraction produced no .class files. "
                                "The Spring Boot fat JAR may not contain application classes "
                                "in the expected location. Inspect the JAR structure."
                            )
                        break
            else:
                print(f"  ✗ No BOOT-INF/classes extraction directory found in classpaths")
                results['issues'].append('NO_APPLICATION_CLASSES_DIR')
                results['recommendations'].append(
                    "The Spring Boot fat JAR's BOOT-INF/classes/ must be extracted "
                    "to a directory and added as a classpath for JaCoCo reporting. "
                    "This is required for bytecode alignment between runtime and report."
                )

            # Check includes vs classpath alignment
            includes = config.get('jacoco', {}).get('includes', [])
            if includes and verbose:
                import zipfile as zf_mod
                print(f"  [verbose] JaCoCo includes filter: {includes}")
                for inc in includes:
                    pkg = inc.replace('.*', '').replace('*', '').replace('.', '/')
                    found_in = []

                    for cp in classpaths:
                        if os.path.isdir(cp):
                            pkg_dir = os.path.join(cp, pkg)
                            if os.path.isdir(pkg_dir):
                                cnt = sum(1 for f in os.listdir(pkg_dir) if f.endswith('.class'))
                                found_in.append(f"{os.path.basename(cp)}/ ({cnt} classes)")
                        elif os.path.isfile(cp) and cp.endswith('.jar'):
                            try:
                                with zf_mod.ZipFile(cp, 'r') as zf:
                                    matching = [n for n in zf.namelist()
                                               if n.startswith(pkg + '/') and n.endswith('.class')]
                                    if matching:
                                        found_in.append(f"{os.path.basename(cp)} ({len(matching)} classes)")
                            except Exception:
                                pass

                    if found_in:
                        print(f"  [verbose] Include '{inc}' → matched in: {', '.join(found_in)}")
                    else:
                        print(f"  [verbose] Include '{inc}' → NOT found in any classpath!")
                        results['issues'].append(f'INCLUDE_NOT_IN_CLASSPATHS:{inc}')

        if verbose:
            print(f"  [verbose] Classpaths list:")
            for i, cp in enumerate(classpaths):
                exists = os.path.exists(cp)
                size = os.path.getsize(cp) if exists and os.path.isfile(cp) else 'dir'
                print(f"    [{i}] {cp} (exists={exists}, size={size})")
    else:
        print("  ○ Skipped (no JaCoCo manager)")

    # ─── Check 7: Coverage Report Content ───
    print("\n[7/9] Checking coverage report content...")
    if target_type in STATE_BASED_TARGETS:
        print("  ○ Skipped (state-based coverage target)")
    elif jacoco_manager and classpaths:
        try:
            xml_path = jacoco_manager.generate_report()
            if xml_path and os.path.exists(xml_path):
                xml_size = os.path.getsize(xml_path)
                results['checks']['report_xml_exists'] = True
                results['checks']['report_xml_size'] = xml_size
                print(f"  ✓ Report generated: {xml_path} ({xml_size:,} bytes)")

                # Use ElementTree for reliable XML parsing (handles any attribute order)
                import xml.etree.ElementTree as ET
                try:
                    tree = ET.parse(xml_path)
                    root = tree.getroot()

                    # Count packages
                    packages = [p.get('name', '') for p in root.findall('.//package')]
                    results['checks']['packages_in_report'] = packages
                    if packages:
                        print(f"  ✓ Found {len(packages)} packages in report:")
                        for pkg in packages[:10]:
                            print(f"    - {pkg}")
                        if len(packages) > 10:
                            print(f"    ... and {len(packages) - 10} more")
                    else:
                        print(f"  ✗ No packages found in report!")
                        results['issues'].append('NO_PACKAGES_IN_REPORT')
                        results['recommendations'].append(
                            "The coverage report XML contains no package entries. "
                            "This means the JaCoCo report tool could not find any classes "
                            "in the provided classpaths."
                        )

                    # Aggregate INSTRUCTION counters from class-level
                    instr_covered = 0
                    instr_missed = 0
                    for cls in root.findall('.//class'):
                        for c in cls.findall('counter'):
                            if c.get('type') == 'INSTRUCTION':
                                instr_covered += int(c.get('covered', 0))
                                instr_missed += int(c.get('missed', 0))

                    # Fallback to report-level counters if class-level is empty
                    if instr_covered == 0 and instr_missed == 0:
                        for c in root.findall('counter'):
                            if c.get('type') == 'INSTRUCTION':
                                instr_covered += int(c.get('covered', 0))
                                instr_missed += int(c.get('missed', 0))

                    instr_total = instr_covered + instr_missed
                    results['checks']['instruction_covered'] = instr_covered
                    results['checks']['instruction_total'] = instr_total

                    if instr_total > 0:
                        pct = (instr_covered / instr_total) * 100
                        print(f"  ✓ Instructions: {instr_covered}/{instr_total} ({pct:.2f}%)")
                        if instr_covered > 0:
                            print(f"  ✓ Coverage is being collected!")
                        else:
                            print(f"  ⚠ Classes found ({instr_total} instructions) but none covered yet")
                            print(f"     (Expected if no fuzzing has been executed)")
                    else:
                        print(f"  ✗ No instruction counters found in report")
                        print(f"     Possible causes:")
                        print(f"     - Exec data probes don't match classpath class IDs (version mismatch)")
                        print(f"     - Agent includes filter not matching runtime classes")
                        print(f"     - Classfiles could not be parsed by JaCoCo CLI")
                        results['issues'].append('NO_INSTRUCTION_COUNTERS')
                        results['recommendations'].append(
                            "No instruction counters found. Verify: "
                            "(1) The authz.jar used for extraction is the SAME version as what's running, "
                            "(2) The JaCoCo agent and CLI are the same version, "
                            "(3) Try using --sourcefiles to add source for better reporting."
                        )

                    # Check for target-specific packages (derived from config.jacoco.includes)
                    matches_target_report = _build_target_matcher(config)
                    target_pkgs = [p for p in packages if matches_target_report(p)]
                    if target_pkgs:
                        print(f"  ✓ Target-specific packages found: {len(target_pkgs)} packages")
                        results['checks']['target_packages_found'] = target_pkgs
                        if verbose:
                            for sp in target_pkgs[:20]:
                                print(f"    - {sp}")
                    elif packages:
                        print(f"  ⚠ No target-matching packages found among {len(packages)} packages")
                        results['issues'].append('TARGET_PACKAGES_NOT_IN_REPORT')
                        results['recommendations'].append(
                            f"Current includes: {config.get('jacoco', {}).get('includes', [])}. "
                            "Verify these match the actual class packages in the application."
                        )

                except ET.ParseError as pe:
                    print(f"  ✗ XML parse error: {pe}")
                    print(f"    Falling back to regex-based parsing...")
                    # Fallback to regex if XML parsing fails
                    with open(xml_path, 'r', errors='replace') as f:
                        content = f.read()
                    packages = re.findall(r'<package name="([^"]+)"', content)
                    results['checks']['packages_in_report'] = packages
                    print(f"  Found {len(packages)} packages via regex")

                    # Try both attribute orders for counter parsing
                    instr_matches = re.findall(
                        r'<counter type="INSTRUCTION" missed="(\d+)" covered="(\d+)"', content
                    )
                    if instr_matches:
                        instr_missed = sum(int(m[0]) for m in instr_matches)
                        instr_covered = sum(int(m[1]) for m in instr_matches)
                    else:
                        instr_matches = re.findall(
                            r'<counter type="INSTRUCTION" covered="(\d+)" missed="(\d+)"', content
                        )
                        instr_covered = sum(int(m[0]) for m in instr_matches) if instr_matches else 0
                        instr_missed = sum(int(m[1]) for m in instr_matches) if instr_matches else 0

                    instr_total = instr_covered + instr_missed
                    results['checks']['instruction_covered'] = instr_covered
                    results['checks']['instruction_total'] = instr_total
                    print(f"  Instructions: {instr_covered}/{instr_total}")

            else:
                print(f"  ✗ Coverage report generation failed")
                results['checks']['report_generation_failed'] = True
                results['issues'].append('REPORT_GENERATION_FAILED')
                results['recommendations'].append(
                    "The JaCoCo report tool failed. This typically means: "
                    "(1) coverage.exec is empty or corrupt, "
                    "(2) classpaths are missing or incorrect, "
                    "(3) the JaCoCo CLI jar is not found."
                )
        except Exception as e:
            print(f"  ✗ Report check failed: {e}")
            results['checks']['report_check_error'] = str(e)
    elif jacoco_manager:
        print(f"  ○ Skipped (no classpaths configured - see Check 6)")
        results['checks']['report_skipped_no_classpaths'] = True
    else:
        print("  ○ Skipped (no JaCoCo manager)")

    # ─── Check 8: End-to-End Coverage Flow Test ───
    print("\n[8/9] Running end-to-end coverage flow test...")
    if target_type in STATE_BASED_TARGETS:
        print("  ○ Skipped (state-based coverage target)")
    elif is_healthy and jacoco_manager:
        # Force re-extract classpaths from running container to ensure bytecode match
        if hasattr(manager, '_prepare_classpaths'):
            print("  Re-extracting classpaths from running container (ensures bytecode match)...")
            manager._prepare_classpaths()
            classpaths = getattr(jacoco_manager, 'classpaths', [])

        if not classpaths:
            print("  ○ Skipped (no classpaths configured)")
        else:
            try:
                # Send a simple HTTP request to trigger some code coverage
                base_url = config.get('oauth', {}).get('base_url', 'http://127.0.0.1:8080')
                import requests as req_lib
                resp = req_lib.get(base_url + '/login', timeout=5)
                print(f"  Sent test request to /login → HTTP {resp.status_code}")

                # Also try the token endpoint with password grant
                token_url = base_url + '/oauth/token'
                oc = config.get('oauth', {})
                token_data = {
                    'grant_type': 'password',
                    'client_id': oc.get('client_id', 'fuzz-client'),
                    'client_secret': oc.get('client_secret', 'fuzz-client-secret'),
                    'username': oc.get('user', 'test'),
                    'password': oc.get('password', 'Test@2015#'),
                    'scope': oc.get('scope', 'read write'),
                }
                resp2 = req_lib.post(token_url, data=token_data, timeout=10)
                print(f"  Sent password grant to /oauth/token → HTTP {resp2.status_code}")

                # Dump coverage again and check if it changed
                agent_port = config.get('jacoco', {}).get('agent_port', 6300)
                exec_path = os.path.join(jacoco_manager.work_dir, 'coverage.exec')
                exec_before = os.path.getsize(exec_path) if os.path.exists(exec_path) else 0

                jacoco_manager.dump_coverage(port=agent_port)

                exec_after_size = os.path.getsize(exec_path) if os.path.exists(exec_path) else 0

                results['checks']['exec_size_before'] = exec_before
                results['checks']['exec_size_after'] = exec_after_size
                results['checks']['exec_size_changed'] = exec_after_size != exec_before

                if exec_after_size != exec_before:
                    print(f"  ✓ Exec file changed after requests ({exec_before} → {exec_after_size} bytes)")
                elif exec_after_size > 0:
                    print(f"  ⚠ Exec file did not change ({exec_after_size} bytes)")
                else:
                    print(f"  ✗ Exec file is empty after requests")
                    results['issues'].append('E2E_NO_COVERAGE_COLLECTED')

                # Analyze exec to see what classes were instrumented
                exec_info = jacoco_manager.exec_info()
                if exec_info:
                    matches_target_e2e = _build_target_matcher(config)
                    target_in_exec = [c for c in exec_info.get('class_ids', {}).keys()
                                      if matches_target_e2e(c)]
                    if target_in_exec:
                        print(f"  ✓ {len(target_in_exec)} target classes found in exec data")
                    else:
                        print(f"  ⚠ No target class names found in exec (may be parsing issue; check report for actual coverage)")

                # Generate final report and check for non-zero coverage
                xml_path = jacoco_manager.generate_report()
                if xml_path and os.path.exists(xml_path):
                    import xml.etree.ElementTree as ET
                    try:
                        tree = ET.parse(xml_path)
                        root = tree.getroot()
                        instr_covered = 0
                        instr_missed = 0
                        for cls in root.findall('.//class'):
                            for c in cls.findall('counter'):
                                if c.get('type') == 'INSTRUCTION':
                                    instr_covered += int(c.get('covered', 0))
                                    instr_missed += int(c.get('missed', 0))
                        if instr_covered == 0 and instr_missed == 0:
                            for c in root.findall('counter'):
                                if c.get('type') == 'INSTRUCTION':
                                    instr_covered += int(c.get('covered', 0))
                                    instr_missed += int(c.get('missed', 0))
                    except ET.ParseError:
                        with open(xml_path, 'r', errors='replace') as f:
                            content = f.read()
                        matches = re.findall(r'covered="(\d+)"', content)
                        instr_covered = sum(int(m) for m in matches)

                    results['checks']['e2e_instruction_covered'] = instr_covered
                    results['checks']['e2e_instruction_total'] = instr_covered + instr_missed
                    if instr_covered > 0:
                        pct = (instr_covered / (instr_covered + instr_missed)) * 100 if (instr_covered + instr_missed) > 0 else 0
                        print(f"  ✓ E2E test: {instr_covered}/{instr_covered + instr_missed} instructions covered ({pct:.2f}%)")
                        print(f"    Coverage collection is WORKING correctly!")
                    elif instr_missed > 0:
                        print(f"  ✗ E2E test: 0/{instr_missed} instructions covered")
                        print(f"    Classes found in report but NO probes matched from exec data")
                        print(f"    This indicates a CLASS ID MISMATCH between runtime and classpath bytecode")
                        results['issues'].append('E2E_CLASS_ID_MISMATCH')
                        results['recommendations'].append(
                            "CLASS ID MISMATCH: The bytecode extracted for reporting does not match "
                            "the bytecode loaded at runtime. Most common cause: cached extracted JARs "
                            "from a previous build. Fix: delete the relevant "
                            "jacoco_tools/{keycloak,sas,cxf,wso2}_lib/extracted/ directory for your "
                            "target and re-run the diagnostic."
                        )
                    else:
                        print(f"  ✗ E2E test: No instruction data in report at all")
                        results['issues'].append('E2E_ZERO_COVERAGE')
                        results['recommendations'].append(
                            "After sending HTTP requests, coverage is still 0%. "
                            "Try deleting the relevant jacoco_tools/*_lib/extracted/ directory and re-running."
                        )
            except Exception as e:
                print(f"  ✗ E2E test failed: {e}")
                results['checks']['e2e_test_error'] = str(e)
    else:
        if not is_healthy:
            print("  ○ Skipped (container not running, use --start to auto-start)")
        else:
            print("  ○ Skipped (no JaCoCo manager)")

    # ─── Check 9: Class ID Verification ───
    print("\n[9/9] Verifying class ID alignment between exec and classpaths...")
    if target_type in STATE_BASED_TARGETS:
        print("  ○ Skipped (state-based coverage target)")
    elif jacoco_manager and classpaths:
        try:
            exec_info = jacoco_manager.exec_info()
            exec_class_ids = exec_info.get('class_ids', {}) if exec_info else {}

            if exec_class_ids:
                # Try to compute classpath class IDs using classinfo
                cp_class_ids = jacoco_manager.compute_classpath_class_ids()

                if cp_class_ids:
                    exec_names = set(exec_class_ids.keys())
                    cp_names = set(cp_class_ids.keys())

                    matching_names = exec_names & cp_names
                    exec_only = exec_names - cp_names
                    cp_only = cp_names - exec_names

                    results['checks']['class_id_matching_names'] = len(matching_names)
                    results['checks']['class_id_exec_only'] = len(exec_only)
                    results['checks']['class_id_cp_only'] = len(cp_only)

                    print(f"  Exec classes: {len(exec_names)}")
                    print(f"  Classpath classes: {len(cp_names)}")
                    print(f"  Matching class names: {len(matching_names)}")

                    if matching_names:
                        # Check if class IDs match for matching names
                        id_matches = 0
                        id_mismatches = 0
                        mismatch_examples = []
                        for name in matching_names:
                            if exec_class_ids[name] == cp_class_ids[name]:
                                id_matches += 1
                            else:
                                id_mismatches += 1
                                if len(mismatch_examples) < 5:
                                    mismatch_examples.append(
                                        f"{name}: exec={exec_class_ids[name]} cp={cp_class_ids[name]}"
                                    )

                        results['checks']['class_id_matches'] = id_matches
                        results['checks']['class_id_mismatches'] = id_mismatches

                        if id_mismatches > 0:
                            print(f"  ✗ CLASS ID MISMATCH: {id_mismatches}/{len(matching_names)} classes have different IDs!")
                            print(f"    This confirms the classpath bytecode doesn't match runtime bytecode")
                            for ex in mismatch_examples:
                                print(f"    - {ex}")
                            results['issues'].append('CLASS_ID_MISMATCH_CONFIRMED')
                            results['recommendations'].append(
                                "CONFIRMED: Class ID mismatch between runtime and classpath bytecode. "
                                "Delete the relevant jacoco_tools/*_lib/extracted/ directory and re-run the diagnostic. "
                                "The framework will re-copy the JAR/WAR from the running container."
                            )
                        elif id_matches > 0:
                            print(f"  ✓ All {id_matches} matching classes have IDENTICAL class IDs")
                            print(f"    Classpath bytecode matches runtime bytecode!")
                        else:
                            print(f"  ⚠ No overlapping classes to compare")
                    else:
                        print(f"  ✗ No class names match between exec and classpaths")
                        if exec_only:
                            print(f"    Exec-only examples: {list(exec_only)[:5]}")
                        if cp_only:
                            print(f"    Classpath-only examples: {list(cp_only)[:5]}")
                        results['issues'].append('NO_OVERLAPPING_CLASSES')
                else:
                    print(f"  ⚠ Could not compute classpath class IDs (classinfo not available)")
                    print(f"    Classes in exec: {list(exec_class_ids.keys())[:5]}")
            else:
                print(f"  ○ Skipped (no class data in exec)")
        except Exception as e:
            print(f"  ✗ Class ID verification failed: {e}")
            if verbose:
                import traceback
                traceback.print_exc()
    else:
        print("  ○ Skipped")

    # ─── Summary ───
    print(f"\n{'='*60}")
    print(f"  Diagnostic Summary ({len(results['checks'])} checks performed)")
    print(f"{'='*60}")

    issue_count = len(results['issues'])
    if issue_count == 0:
        print(f"  ✓ No issues found - coverage collection appears to be working")
    else:
        print(f"  ✗ Found {issue_count} issue(s):")
        for i, issue in enumerate(results['issues'], 1):
            print(f"    {i}. {issue}")

    if results['recommendations']:
        print(f"\n  Recommendations:")
        for i, rec in enumerate(results['recommendations'], 1):
            print(f"    {i}. {rec}")

    print(f"{'='*60}\n")

    # Save diagnostic results
    output_dir = config.get('output_dir', 'out/oauth_coverage')
    os.makedirs(output_dir, exist_ok=True)
    diag_path = os.path.join(output_dir, f'diagnostic_{target_type}_{int(time.time())}.json')
    with open(diag_path, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Diagnostic results saved: {diag_path}")

    return issue_count == 0


def save_results_summary(fuzzer, config):
    """Save fuzzing results summary"""
    output_dir = config.get('output_dir', 'out/oauth_coverage')
    os.makedirs(output_dir, exist_ok=True)
    
    target_type = config.get('target_type', 'keycloak')
    
    # For state-based targets, get coverage from go_coverage manager if available
    current_cov = fuzzer.current_coverage
    peak_cov = current_cov  # Default to current if no peak tracking

    if target_type in STATE_BASED_TARGETS and hasattr(fuzzer, 'go_coverage') and fuzzer.go_coverage:
        try:
            go_data = fuzzer.go_coverage.collect_coverage()
            if go_data and go_data.coverage_percentage > 0:
                current_cov = go_data
            # Get peak coverage for proper reporting
            if hasattr(fuzzer.go_coverage, 'max_coverage') and fuzzer.go_coverage.max_coverage:
                peak_cov = fuzzer.go_coverage.max_coverage
            elif hasattr(fuzzer.go_coverage, 'peak_coverage_percentage'):
                peak_cov = current_cov
                peak_cov.coverage_percentage = fuzzer.go_coverage.peak_coverage_percentage
        except Exception:
            pass
    
    # Calculate coverage increase from baseline to PEAK (not current)
    initial_baseline = getattr(fuzzer, 'initial_baseline_coverage', fuzzer.baseline_coverage)
    coverage_increase = peak_cov.coverage_percentage - initial_baseline.coverage_percentage
    
    summary = {
        'target_type': target_type,
        'fuzzing_session': {
            'total_executions': fuzzer.execution_count,
            'interesting_cases': len(fuzzer.interesting_cases),
            'mutation_count': fuzzer.mutation_count,
            'final_coverage_percentage': current_cov.coverage_percentage,
            'peak_coverage_percentage': peak_cov.coverage_percentage,
            'baseline_coverage_percentage': initial_baseline.coverage_percentage,
            'coverage_increase': coverage_increase
        },
        'coverage_details': {
            'instructions_covered': current_cov.instructions_covered,
            'instructions_total': current_cov.instructions_total,
            'lines_covered': getattr(current_cov, 'lines_covered', 0),
            'lines_total': getattr(current_cov, 'lines_total', 0),
            'branches_covered': getattr(current_cov, 'branches_covered', 0),
            'branches_total': getattr(current_cov, 'branches_total', 0),
            'methods_covered': getattr(current_cov, 'methods_covered', 0),
            'methods_total': getattr(current_cov, 'methods_total', 0),
            'classes_covered': getattr(current_cov, 'classes_covered', 0),
            'classes_total': getattr(current_cov, 'classes_total', 0)
        },
        'interesting_cases_summary': (
            [
                {
                    'case_id': i + 1,
                    'coverage_percentage': case.get('coverage', {}).get('coverage_percentage', 0.0),
                    'status_code': case.get('response', {}).get('status_code', 'ERROR'),
                    'timestamp': case.get('timestamp', 0),
                    'execution_count': case.get('execution_count', 0)
                }
                for i, case in enumerate(fuzzer.interesting_cases)
            ] if getattr(fuzzer, '_save_interesting_cases', True) else []
        ),
        'configuration': {k: v for k, v in config.items() 
                         if k not in ('_kc_manager', '_authelia_manager', '_target_manager')},
        'timestamp': time.time()
    }
    
    summary_file = os.path.join(output_dir, 'fuzzing_summary.json')
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"Results summary saved: {summary_file}")

    # Full interesting-case dump (one JSON per line): sequence + overrides +
    # oracle hits + coverage context. This is the post-hoc corpus-replay
    # input and the oracle-funnel raw evidence.
    if getattr(fuzzer, 'interesting_cases', None):
        cases_path = os.path.join(output_dir, 'interesting_cases.jsonl')
        n_written = 0
        with open(cases_path, 'w') as f:
            for case in fuzzer.interesting_cases:
                try:
                    f.write(json.dumps(case, default=str) + '\n')
                    n_written += 1
                except Exception:
                    pass
        print(f"Interesting cases dump: {cases_path} ({n_written} cases)")
    
    # Print key statistics
    print(f"\n=== Fuzzing Results Summary ===")
    print(f"Target: {target_type}")
    print(f"Total executions: {fuzzer.execution_count}")
    print(f"Interesting cases found: {len(fuzzer.interesting_cases)}")
    print(f"Final coverage: {fuzzer.current_coverage.coverage_percentage:.2f}%")
    print(f"Coverage increase: {summary['fuzzing_session']['coverage_increase']:.2f}%")
    print(f"Instructions covered: {fuzzer.current_coverage.instructions_covered}/{fuzzer.current_coverage.instructions_total}")
    print(f"Lines covered: {fuzzer.current_coverage.lines_covered}/{fuzzer.current_coverage.lines_total}")
    print(f"Branches covered: {fuzzer.current_coverage.branches_covered}/{fuzzer.current_coverage.branches_total}")


def main():
    """Main entry point with multi-target support and enhanced modes"""
    parser = argparse.ArgumentParser(description='OAuth fuzzing with multi-target support')
    parser.add_argument('--config', default='configs/oauth_java_coverage.json', help='Configuration file')
    parser.add_argument(
        '--target',
        choices=['keycloak', 'authelia', 'spring_authz', 'cxf_oauth', 'wso2',
                 'casdoor', 'ory_hydra', 'zitadel', 'shiro', 'authentik',
                 'simplelogin', 'nodeoidc', 'logto', 'auto'],
        default='auto',
        help='Target OAuth provider (auto reads from config)'
    )
    parser.add_argument('--iterations', type=int, default=1000, help='Number of fuzzing iterations')
    parser.add_argument('--check-deps', action='store_true', help='Check dependencies only')
    parser.add_argument('--mode', choices=['coverage', 'aflnet', 'auth-test', 'security-scan', 'diagnose'],
                       default='coverage',
                       help='Fuzzing mode: coverage (basic), aflnet (sequence-based), '
                            'auth-test (test auth flow), security-scan (security-focused), '
                            'diagnose (troubleshoot coverage collection)')
    parser.add_argument('--adapter', choices=['none', 'boofuzz', 'selenium', 'both'], default='none',
                       help='External adapter for OAuthFuzz mode')
    parser.add_argument('--security-mode', action='store_true', help='Enable security-focused testing')
    parser.add_argument('--verbose', action='store_true', help='Verbose diagnostic output')
    parser.add_argument('--start', action='store_true',
                       help='Start target container if not running (for diagnose mode)')
    parser.add_argument('--set', action='append', default=[], metavar='key=value',
                       help='Config override, dot-path (e.g. fuzzing.budget_protocol_steps=10000)')
    parser.add_argument('--fuzzer-class', default=None, metavar='module:Class',
                       help='module:ClassName replacing AFLNetMinimalFuzzer in aflnet mode')
    args = parser.parse_args()

    # Determine target type
    if args.target == 'auto' and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            cfg = json.load(f)
        target_type = cfg.get('target_type', 'keycloak').lower()
        if target_type == 'java_based':
            target_type = 'keycloak'
    else:
        target_type = args.target if args.target != 'auto' else 'keycloak'

    print(f"Target type: {target_type}")

    # Check dependencies
    if not check_dependencies(target_type):
        print("Dependency check failed. Please install missing dependencies.")
        sys.exit(1)

    if args.check_deps:
        print("All dependencies are available!")
        return

    # Enable security mode if requested
    mode = args.mode
    if args.security_mode and mode not in ('security-scan',):
        mode = 'security-scan'

    # Handle diagnostic mode separately (no fuzzing needed)
    if mode == 'diagnose':
        ok = run_diagnostic(args.config, target_type, verbose=args.verbose, start_if_needed=args.start)
        sys.exit(0 if ok else 1)

    # Run fuzzing session
    success = run_fuzzing_session(args.config, args.iterations, mode, args.adapter,
                                  config_overrides=args.set, fuzzer_class=args.fuzzer_class)

    if success:
        print("\n🎉 Fuzzing session completed successfully!")
        print("Check the output directory for results and coverage reports.")
    else:
        print("\n❌ Fuzzing session failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
