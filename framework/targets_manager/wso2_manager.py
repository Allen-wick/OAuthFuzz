#!/usr/bin/env python3
"""
WSO2 Identity Server Manager

Target: https://github.com/wso2/product-is
Uses official Docker image wso2/wso2is:7.0.0.

OAuth/OIDC endpoints:
  - /oauth2/authorize
  - /oauth2/token
  - /oauth2/userinfo
  - /oauth2/introspect
  - /oauth2/revoke
  - /oauth2/par (RFC 9126)
  - /oauth2/jwks
  - /oauth2/oidcdiscovery/.well-known/openid-configuration

Authentication endpoints:
  - /authenticationendpoint/login.do
  - /commonauth (POST target for login)
  - /authenticationendpoint/oauth2_consent.do

Admin APIs:
  - /api/identity/oauth2/dcr/v1.1/register
  - /scim2/Users

CVE refs: CVE-2024-6914 (unauth IDOR), CVE-2023-6833 (XSS in admin console),
          CVE-2023-6835, CVE-2022-29548.
"""

import os, subprocess, time, requests, json, shutil, re
from typing import Dict
try:
    from core.coverage import JaCoCoManager
except ImportError:
    JaCoCoManager = None
from targets_manager.base import TargetManager

from core.paths import PROJECT_ROOT


class Wso2Manager(TargetManager):
    def __init__(self, config: Dict):
        super().__init__(config)  # base init: _atexit_registered etc.
        self.config = config
        wc = config.get('wso2', {})
        oauth_cfg = config.get('oauth', {})
        self.base_url = oauth_cfg.get('base_url', 'https://127.0.0.1:9443')
        self.container_name = wc.get('container_name', 'wso2is-fuzz')
        self.image = wc.get('image', 'wso2/wso2is:7.0.0')
        self.http_port = wc.get('http_port', 9763)
        self.https_port = wc.get('https_port', 9443)
        self.config_dir = os.path.abspath(wc.get('config_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'wso2_service', 'config')))
        self.work_dir = os.path.abspath(wc.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'wso2_service', 'work')))
        self.startup_timeout = wc.get('startup_timeout', 300)
        self.admin_user = wc.get('admin_username', 'admin')
        self.admin_pass = wc.get('admin_password', 'admin')

        self._dcr_provisioned = False

        self.discovery_endpoint = f"{self.base_url}/oauth2/oidcdiscovery/.well-known/openid-configuration"
        self.health_check_url = self.discovery_endpoint

        self.jacoco_enabled = wc.get('jacoco_enabled', True)
        self.jacoco = None
        if self.jacoco_enabled and JaCoCoManager:
            jc = config.get('jacoco', {})
            self.jacoco = JaCoCoManager(
                work_dir=jc.get('work_dir', 'jacoco_tools'),
                version=jc.get('version', '0.8.14'))
            # WSO2's OSGi runtime produces legitimately large exec files
            # (250-350 MB cumulative). The default 50 MB disk guard in
            # core/coverage.py would refuse every report. Lift the ceiling
            # so generate_report() actually runs.
            try:
                self.jacoco.max_exec_mb = int(
                    jc.get('max_exec_mb_wso2', 800))
            except Exception:
                self.jacoco.max_exec_mb = 800

    def start(self) -> bool:
        print("=" * 70)
        print("Starting WSO2 Identity Server 7.0.0")
        print("=" * 70)
        self._cleanup()
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)

        if not self._start_container(): return False
        if not self._wait_ready(): self._print_logs(); return False
        if not self._provision_fuzz_client():
            print("[WSO2] Warning: fuzz-client provisioning failed; fuzzing will use default client")
        if self.jacoco:
            self._prepare_classpaths()
        return True

    def stop(self) -> None:
        # Only attempt a coverage dump if the container is actually running
        # AND the JaCoCo agent port is reachable. Otherwise we just flood the
        # console with 'Connection refused' retries.
        dump_ok = False
        if self.jacoco and self._container_running():
            try:
                jp = self.config.get('jacoco', {}).get('agent_port', 6300)
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    if s.connect_ex(('127.0.0.1', jp)) == 0:
                        try:
                            dump_ok = self.jacoco.dump_coverage(port=jp)
                        except Exception as e:
                            print(f"[WSO2] Dump failed: {e}")
                    else:
                        print(f"[WSO2] Skipping dump: JaCoCo agent not listening on {jp}")
            except Exception as e:
                print(f"[WSO2] Dump skipped: {e}")
        # Always clean up the container, regardless of dump outcome.
        self._cleanup()

    def _container_running(self) -> bool:
        try:
            r = subprocess.run(
                ['docker', 'inspect', '-f', '{{.State.Running}}', self.container_name],
                capture_output=True, text=True, timeout=5)
            return r.returncode == 0 and r.stdout.strip() == 'true'
        except Exception:
            return False

    def is_healthy(self) -> bool:
        try:
            r = requests.get(self.discovery_endpoint, timeout=5, verify=False)
            return r.status_code == 200
        except Exception:
            return False

    def _cleanup(self):
        subprocess.run(['docker', 'rm', '-f', self.container_name], capture_output=True)

    def restart(self) -> bool:
        """Stop and restart the WSO2 container. Returns True on success.
        Used by validation tests that need a cold JVM (e.g., DCL singleton
        initialization probes)."""
        print("[WSO2] Restarting container for cold-start test...")
        self._cleanup()
        time.sleep(2)
        if not self._start_container():
            print("[WSO2] Restart failed: container did not start")
            return False
        if not self._wait_ready():
            self._print_logs()
            print("[WSO2] Restart failed: server did not become ready")
            return False
        # Re-provision the fuzz client after restart (H2 DB is fresh)
        self._provision_fuzz_client()
        # Prepare classpaths for JaCoCo if enabled
        if self.jacoco:
            self._prepare_classpaths()
        print("[WSO2] Container restarted and ready.")
        return True

    def _ensure_image(self) -> bool:
        """Pull the WSO2 image with live progress visible to the user.

        Docker auto-pull inside ``subprocess.run(…, capture_output=True)``
        hides the progress bar and blocks for minutes on slow networks
        with zero feedback — indistinguishable from a hang.  We pre-pull
        explicitly so the user sees layer-by-layer progress on stderr.
        """
        # Check if image exists locally first
        check = subprocess.run(
            ['docker', 'image', 'inspect', self.image],
            capture_output=True, text=True, timeout=10)
        if check.returncode == 0:
            return True

        print(f"[WSO2] Image '{self.image}' not found locally.")
        print(f"[WSO2] Pulling (this may take several minutes on first run)...")
        r = subprocess.run(
            ['docker', 'pull', self.image],
            # Let stdout/stderr pass through so pull progress is visible
            capture_output=False, timeout=None)
        if r.returncode != 0:
            print(f"[WSO2] ERROR: docker pull failed with code {r.returncode}")
            return False
        return True

    def _start_container(self) -> bool:
        # Ensure the image is pulled BEFORE `docker run`, so the user sees
        # pull progress and the subprocess.run below is fast.
        if not self._ensure_image():
            return False

        host_jc_dir = os.path.abspath(self.jacoco.work_dir) if self.jacoco else '/tmp/jacoco'
        if self.jacoco:
            # JaCoCoManager.__init__ already calls _download_and_extract_tools()
            # automatically; there is no _download_if_needed method. We only
            # need to verify the agent JAR ended up at the host bind-mount path.
            agent_jar_path = os.path.join(host_jc_dir, 'jacocoagent.jar')
            if not os.path.isfile(agent_jar_path):
                print(f"[WSO2] ERROR: jacocoagent.jar not found at "
                      f"{agent_jar_path}; coverage will be disabled")
                # Fall back to running without agent
                self.jacoco = None

        jacoco_cfg = self.config.get('jacoco', {})
        agent_port = jacoco_cfg.get('agent_port', 6300)
        includes = jacoco_cfg.get('includes', [
            'org.wso2.carbon.identity.oauth.*',
            'org.wso2.carbon.identity.oauth2.*',
            'org.wso2.carbon.identity.openidconnect.*',
            'org.wso2.carbon.identity.application.authentication.*',
        ])

        java_opts_parts = []
        if self.jacoco:
            agent_opts = (f"output=tcpserver,address=0.0.0.0,port={agent_port},"
                          f"includes={':'.join(includes)}")
            agent_arg = f"-javaagent:/opt/jacoco/jacocoagent.jar={agent_opts}"
            java_opts_parts.append(agent_arg)
        java_opts_parts.append("-Xmx2048m")
        java_opts = " ".join(java_opts_parts)

        cmd = [
            'docker', 'run', '-d', '--name', self.container_name,
            '-p', f'{self.http_port}:9763',
            '-p', f'{self.https_port}:9443',
        ]
        # Only expose the JaCoCo port if coverage agent is being loaded
        if self.jacoco:
            cmd.extend(['-p', f'{agent_port}:{agent_port}'])
        # Bind-mount WSO2 log directory so validation tests can read
        # wso2carbon.log directly from the host without docker exec.
        host_log_dir = os.path.join(os.path.dirname(self.work_dir), 'logs')
        os.makedirs(host_log_dir, exist_ok=True)
        cmd.extend([
            '-v', f'{host_log_dir}:/home/wso2carbon/wso2is-7.0.0/repository/logs',
            '-v', f'{host_jc_dir}:/opt/jacoco',
            '-e', f'JAVA_OPTS={java_opts}',
            self.image
        ])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[WSO2] docker run failed: {r.stderr}")
            return False

        # Verify the container actually started (didn't immediately exit
        # due to JVM crash, missing agent jar, port conflict, etc.)
        time.sleep(3)
        if not self._container_running():
            print("[WSO2] Container exited immediately after docker run.")
            print("[WSO2] Last 30 lines of container log:")
            logs = subprocess.run(
                ['docker', 'logs', '--tail', '30', self.container_name],
                capture_output=True, text=True, timeout=10)
            for line in (logs.stdout + logs.stderr).splitlines():
                print(f"  {line}")
            return False

        return True

    def _wait_ready(self) -> bool:
        start = time.time()
        print(f"[WSO2] Waiting for server (timeout={self.startup_timeout}s)...")
        stable_hits = 0
        last_progress = -15  # Force first progress line at t=0
        diag_printed = False
        while time.time() - start < self.startup_timeout:
            discovery_ok = self.is_healthy()

            auth_ok = False
            auth_status = None
            auth_body_marker = ''
            if discovery_ok:
                try:
                    r2 = requests.get(
                        f"{self.base_url}/authenticationendpoint/login.do",
                        timeout=5, verify=False, allow_redirects=False)
                    auth_status = r2.status_code
                    body = r2.text or ''
                    auth_body_marker = (
                        'WSO2' if 'WSO2' in body
                        else 'login' if 'login' in body.lower()
                        else 'sessionDataKey'[:20] if 'sessionDataKey' in body
                        else ''
                    )
                    auth_ok = (
                        auth_status in (200, 302)
                        and ('sessionDataKey' in body
                             or 'WSO2' in body
                             or 'login' in body.lower()
                             or auth_status == 302)
                    )
                except Exception:
                    pass

            if discovery_ok and auth_ok:
                stable_hits += 1
                if stable_hits >= 3:
                    elapsed = time.time() - start
                    print(f"[WSO2] Server ready after {elapsed:.0f}s "
                          f"(3 consecutive stable probes)")
                    return True
            else:
                stable_hits = 0
                # One-shot diagnostic — print WHY we're not ready yet
                if not diag_printed and time.time() - start > 15:
                    diag_printed = True
                    parts = []
                    if discovery_ok:
                        parts.append(f"discovery=200")
                    else:
                        parts.append("discovery=unreachable")
                    if auth_status is not None:
                        marker = f" ({auth_body_marker})" if auth_body_marker else ""
                        parts.append(f"login.do={auth_status}{marker}")
                    else:
                        parts.append("login.do=unreachable")
                    print(f"[WSO2] Not ready yet: {', '.join(parts)} "
                          f"- server may still be starting...")

            elapsed_int = int(time.time() - start)
            if elapsed_int - last_progress >= 30:
                last_progress = elapsed_int
                status_bits = [f"discovery={'200' if discovery_ok else '✗'}"]
                if auth_status is not None:
                    marker = f" ({auth_body_marker})" if auth_body_marker else ""
                    status_bits.append(f"login.do={auth_status}{marker}")
                else:
                    status_bits.append("login.do=✗")
                print(f"[WSO2] Still waiting... ({elapsed_int}s elapsed, "
                      f"stable_hits={stable_hits}) [{', '.join(status_bits)}]")
            time.sleep(5)
        return False

    def _provision_fuzz_client(self) -> bool:
        """Register a fuzz-client via WSO2 DCR (Dynamic Client Registration).

        WSO2 IS 7.x uses /api/identity/oauth2/dcr/v1.1/register.
        The endpoint requires admin Basic auth.  We register a client
        with all grant types needed for comprehensive fuzzing.

        NOTE: WSO2's DCR Jackson deserialization rejects unknown fields.
        The `scope` field and `ext_param_client_id`/`ext_param_client_secret`
        are NOT part of RFC 7591 and cause 400 "Unrecognized field" errors.
        WSO2 auto-generates client_id and client_secret on success.
        """
        oauth_cfg = self.config.get('oauth', {})
        client_name = oauth_cfg.get('client_id', 'fuzz-client')
        redirect_uri = oauth_cfg.get('redirect_uri', 'http://127.0.0.1:7777/callback')
        dcr_url = f"{self.base_url}/api/identity/oauth2/dcr/v1.1/register"
        payload = {
            "client_name": client_name,
            "grant_types": ["authorization_code", "refresh_token",
                            "password", "client_credentials",
                            "urn:ietf:params:oauth:grant-type:jwt-bearer"],
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "client_secret_post",
            # DO NOT send `scope` — WSO2 7.0.0 DCR rejects it as unknown.
            # DO NOT send `ext_param_client_id` / `ext_param_client_secret` —
            # WSO2 auto-generates client_id and client_secret on success.
        }

        try:
            r = requests.post(dcr_url, json=payload,
                              auth=(self.admin_user, self.admin_pass),
                              verify=False, timeout=15)
            if r.status_code in (200, 201):
                resp_data = r.json()
                actual_id = resp_data.get('client_id', client_name)
                actual_secret = resp_data.get('client_secret', '')
                print(f"[WSO2] Fuzz client provisioned: client_id={actual_id}")
                oauth_cfg['client_id'] = actual_id
                oauth_cfg['client_secret'] = actual_secret
                # DCR writes propagate asynchronously through the Carbon
                # registry; token_endpoint won't recognize the client
                # for 1-2 seconds.
                time.sleep(3)
                self._dcr_provisioned = True
                return True
            if r.status_code == 400:
                error_desc = ''
                try:
                    body = r.json()
                    # WSO2 DCR error responses use "error_description" (with
                    # underscore), not "description". Try both keys so the
                    # detection works regardless of WSO2 version.
                    error_desc = body.get('error_description',
                                 body.get('description', ''))
                except Exception:
                    error_desc = r.text[:200]
                # Fallback: if JSON parsing didn't yield a description,
                # search the raw response text.
                if not error_desc:
                    error_desc = (r.text or '')[:300]
                # WSO2's actual wording is "already exist" (not "already
                # exists"), so match the shorter substring. Also keep the
                # plural variant for forward/backward compatibility.
                if ('already exist' in error_desc.lower()
                        or 'already exists' in error_desc.lower()):
                    print(f"[WSO2] Client '{client_name}' already exists; using existing client")
                    self._dcr_provisioned = True
                    return True
            print(f"[WSO2] DCR returned {r.status_code}: {r.text[:200]}")
            return False
        except Exception as e:
            print(f"[WSO2] DCR failed: {e}")
            return False

    def _prepare_classpaths(self) -> None:
        """Copy relevant OSGi bundle JARs from WSO2 plugins dir, then unpack
        into ONE unified classes/ tree that JaCoCo can analyse without
        hitting duplicate‑FQN errors.

        WSO2 IS ships Axis2 WSDL→Java stubs (`*.stub_*.jar`) that each
        regenerate the same XSD‑derived classes
        (e.g. org/wso2/carbon/identity/base/xsd/IdentityException$Factory)
        with *different bytecode*. Passing them all to
        `jacococli report --classfiles` makes CoverageBuilder throw
        `java.lang.IllegalStateException: Can't add different class with
        same name …` and abort the whole report. The stubs carry zero
        fuzzing value, so we blacklist them here and also first‑writer‑wins
        deduplicate the residual bundles at unpack time.
        """
        import shutil
        import zipfile

        lib_dir = os.path.join(os.path.abspath(self.jacoco.work_dir), 'wso2_lib')
        os.makedirs(lib_dir, exist_ok=True)

        patterns = [
            'org.wso2.carbon.identity.oauth',
            'org.wso2.carbon.identity.oauth2',
            'org.wso2.carbon.identity.oauth.dcr',
            'org.wso2.carbon.identity.oauth.par',
            'org.wso2.carbon.identity.openidconnect',
            'org.wso2.carbon.identity.application.authentication',
            'org.wso2.carbon.identity.application.authz',
            'org.wso2.carbon.identity.authorization',
            'org.wso2.carbon.identity.discovery',
            'org.wso2.carbon.identity.consent',
            'org.wso2.carbon.identity.user',
            'org.wso2.carbon.identity.core',
        ]

        # Auto‑generated / non‑server bundles with duplicate FQNs — exclude.
        blacklist_substrings = [
            '.stub_',          # Axis2 WSDL→Java stubs (root cause)
            '.ui_',            # Carbon UI fragment bundles
            '.common.ui_',
            '.feature_',       # p2 feature descriptors
            '.sample_',
            '.test_',
        ]

        find_home = subprocess.run(
            ['docker', 'exec', self.container_name,
             'sh', '-c', 'ls -d /home/wso2carbon/wso2is-*/'],
            capture_output=True, text=True)
        wso2_home = find_home.stdout.strip().rstrip('/')
        if not wso2_home:
            wso2_home = '/home/wso2carbon/wso2is-7.0.0'
            print(f"[WSO2] Warning: could not detect WSO2 home, using {wso2_home}")

        plugins_dir = f'{wso2_home}/repository/components/plugins/'
        r = subprocess.run(
            ['docker', 'exec', self.container_name,
             'sh', '-c', f'ls {plugins_dir}'],
            capture_output=True, text=True)
        jar_names = [ln.strip() for ln in r.stdout.split('\n') if ln.strip().endswith('.jar')]
        matched = [
            j for j in jar_names
            if any(p in j for p in patterns)
            and not any(b in j for b in blacklist_substrings)
        ]

        jar_paths = []
        skipped_stubs = []
        for jar in matched:
            out = os.path.join(lib_dir, jar)
            src = f'{self.container_name}:{plugins_dir}{jar}'
            cp_result = subprocess.run(['docker', 'cp', src, out],
                                       capture_output=True, text=True)
            if cp_result.returncode != 0:
                print(f"[WSO2] Warning: docker cp failed for {jar}: {cp_result.stderr[:100]}")
                continue
            if os.path.exists(out):
                jar_paths.append(out)

        # Report how many stubs were filtered so operators can sanity‑check.
        stub_count = sum(
            1 for j in jar_names
            if any(p in j for p in patterns) and any(b in j for b in blacklist_substrings)
        )

        if not jar_paths:
            print(f"[WSO2] Warning: no OAuth bundles found in {plugins_dir}")
            return

        # Build ONE unified class‑file tree so JaCoCo never sees the same
        # FQN twice. First‑writer‑wins: for residual duplicates across
        # service bundles (Require‑Bundle / Import‑Package overlap), the
        # running JVM has loaded exactly one variant anyway; picking any
        # deterministic variant yields a consistent bytecode hash.
        classes_dir = os.path.join(lib_dir, 'classes')
        if os.path.isdir(classes_dir):
            shutil.rmtree(classes_dir, ignore_errors=True)
        os.makedirs(classes_dir, exist_ok=True)

        total_written = 0
        total_dupes = 0
        for jar_path in jar_paths:
            try:
                with zipfile.ZipFile(jar_path, 'r') as zf:
                    for member in zf.namelist():
                        if not member.endswith('.class'):
                            continue
                        # Skip JDK‑version overlays and manifest entries
                        # (multi‑release classes also trigger dup errors).
                        if member.startswith('META-INF/'):
                            continue
                        dst = os.path.join(classes_dir, member)
                        if os.path.exists(dst):
                            total_dupes += 1
                            continue  # first‑writer‑wins
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        with zf.open(member) as sf, open(dst, 'wb') as df:
                            df.write(sf.read())
                        total_written += 1
            except Exception as e:
                print(f"[WSO2] Warning: failed to unpack "
                      f"{os.path.basename(jar_path)}: {e}")

        # Feed JaCoCo ONE --classfiles pointing at the unified tree.
        self.jacoco.set_classpaths([classes_dir])
        print(f"[WSO2] JaCoCo classpaths: 1 unified tree from "
              f"{len(jar_paths)} OSGi bundles "
              f"({total_written} classes, {total_dupes} duplicates de‑duped, "
              f"{stub_count} stub/UI bundles blacklisted) at {classes_dir}")

    def _jacoco_dump(self):
        """Best-effort JaCoCo dump. Never block teardown longer than 8 s."""
        import socket, threading, subprocess
        try:
            # Probe the TCP port first — if the agent is gone, skip.
            with socket.create_connection(('127.0.0.1', 6300), timeout=1):
                pass
        except Exception:
            print("[JaCoCo] agent port 6300 unreachable, skipping dump")
            return

        done = threading.Event()
        def _do():
            try:
                subprocess.run(
                    ['java', '-jar', self.jacococli_path,
                     'dump', '--address', '127.0.0.1', '--port', '6300',
                     '--destfile', self.coverage_exec],
                    check=False, timeout=8)
            finally:
                done.set()

        t = threading.Thread(target=_do, daemon=True)
        t.start()
        if not done.wait(timeout=8):
            print("[JaCoCo] Dump did not complete in 8s; continuing cleanup")
        # No join — daemon thread will die with the process.

    def dump_coverage(self, *args, **kwargs):
        """Dump coverage; additionally rotate the .exec file once it passes
        a size threshold so the report generator never refuses to run.

        The 8 000-iter log showed coverage stagnating at 22.39% from it≈440
        onwards because every subsequent dump printed:
            [JaCoCo] WARNING: exec file is 51 MB — refusing to generate
        A rotating file keeps per-dump exec sizes bounded and restores
        coverage-guided selection for the full run.
        """
        import os, time, shutil
        result = super().dump_coverage(*args, **kwargs) if hasattr(
            super(), 'dump_coverage') else None

        try:
            exec_path = getattr(self, 'coverage_exec',
                                os.path.join(PROJECT_ROOT, 'jacoco_tools', 'coverage.exec'))
            if os.path.isfile(exec_path):
                size_mb = os.path.getsize(exec_path) / (1024 * 1024)
                # Rotate at 40 MB so we never hit the 51 MB refusal line.
                if size_mb > 40:
                    rotated = f"{exec_path}.{int(time.time())}"
                    shutil.move(exec_path, rotated)
                    print(f"[JaCoCo] Rotated coverage.exec ({size_mb:.1f} MB) -> {rotated}")
        except Exception as e:
            print(f"[JaCoCo] Rotation skipped: {e}")
        return result

    def import_config(self, config_file=None) -> bool:
        """WSO2 uses DCR for client provisioning, no file import needed.

        Only attempts DCR if it wasn't already attempted in start() —
        avoids a duplicate 400 error when the first attempt already
        logged a clear failure message.
        """
        if self._dcr_provisioned:
            return True
        return self._provision_fuzz_client()

    def _print_logs(self, tail: int = 80):
        r = subprocess.run(['docker', 'logs', '--tail', str(tail), self.container_name],
                           capture_output=True, text=True)
        print(r.stdout); print(r.stderr)


def create_test_config_wso2() -> str:
    config = {
        "name": "oauth-wso2-fuzzer",
        "target_type": "wso2",
        "protocol": "OAUTH",
        "implementation": "WSO2 Identity Server 7.0.0",
        "output_dir": "out/oauth_wso2_coverage",
        "oauth": {
            "base_url": "https://127.0.0.1:9443",
            "realm": "carbon.super",
            "client_id": "fuzz-client", "client_secret": "fuzz-client-secret",
            "redirect_uri": "http://127.0.0.1:7777/callback",
            "user": "admin", "password": "admin",
            "scope": "openid profile",
            "verify_ssl": False
        },
        "wso2": {
            "image": "wso2/wso2is:7.0.0",
            "http_port": 9763, "https_port": 9443,
            "startup_timeout": 300, "jacoco_enabled": True,
            "admin_username": "admin", "admin_password": "admin"
        },
        "jacoco": {
            "work_dir": "jacoco_tools", "agent_port": 6300,
            "includes": [
                "org.wso2.carbon.identity.oauth.*",
                "org.wso2.carbon.identity.oauth2.*",
                "org.wso2.carbon.identity.openidconnect.*"
            ]
        },
        "fuzzing": {"max_iterations": 3000, "differential_coverage": True}
    }
    os.makedirs("configs", exist_ok=True)
    path = "configs/oauth_wso2.json"
    with open(path, 'w') as f: json.dump(config, f, indent=2)
    return path