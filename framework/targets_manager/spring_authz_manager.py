#!/usr/bin/env python3
"""
Spring Authorization Server Manager for OAuth Fuzzing Framework

Target: https://github.com/spring-projects/spring-authorization-server
Reference sample: samples/demo-authorizationserver

This manager:
  1. Clones or mounts the SAS source tree
  2. Builds the demo-authorizationserver Spring Boot JAR with Maven
  3. Runs it in Docker with JaCoCo agent
  4. Provides JaCoCo classpath extraction (BOOT-INF/lib filter by
     spring-security-oauth2-authorization-server-*)
  5. Pre-provisions a fuzz-client via ClientRegistrationRepository

CVE history:
  - CVE-2024-38827 (authorization codes issue)
  - CVE-2024-38819 (resource path matching)
  - CVE-2023-20862 (logout bypass)
  - CVE-2023-20860 (regex-based path matching bypass)

Endpoints exposed (OAuth 2.1 + OIDC1):
  - GET  /oauth2/authorize
  - POST /oauth2/token
  - POST /oauth2/introspect    (RFC 7662)
  - POST /oauth2/revoke        (RFC 7009)
  - POST /oauth2/par           (RFC 9126)
  - GET  /userinfo             (OIDC)
  - GET  /oauth2/jwks
  - GET  /.well-known/openid-configuration
  - GET  /.well-known/oauth-authorization-server
"""

import os
import subprocess
import time
import shutil
import zipfile
import tarfile
import io
import hashlib
import requests
import json
from typing import Dict, Optional, List

try:
    from core.coverage import JaCoCoManager
except ImportError:
    JaCoCoManager = None

from targets_manager.base import TargetManager

from core.paths import PROJECT_ROOT

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SAS_SOURCE_DIR = os.path.join(PROJECT_ROOT, 'targets_manager', 'spring_authz_service', 'source')
SAS_OFFLINE_DIR = os.path.join(PROJECT_ROOT, 'targets_manager', 'spring_authz_service', 'offline')   # vendored bundle


class SpringAuthzManager(TargetManager):
    """Spring Authorization Server target manager."""

    def __init__(self, config: Dict):
        super().__init__(config)
        sas_cfg = config.get('spring_authz', {})
        oauth_cfg = config.get('oauth', {})

        self.base_url = oauth_cfg.get('base_url', 'http://127.0.0.1:9000')
        self.container_name = sas_cfg.get('container_name', 'sas-fuzz')
        self.image = sas_cfg.get('image', 'sas-fuzz:latest')
        self.http_port = sas_cfg.get('http_port', 9000)
        self.work_dir = os.path.abspath(sas_cfg.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'spring_authz_service', 'work')))
        self.startup_timeout = sas_cfg.get('startup_timeout', 180)
        self.sample_module = sas_cfg.get('sample_module', 'samples/demo-authorizationserver')

        # Offline-first: pre-built artifacts shipped in the repository
        self.offline_dir = os.path.abspath(
            sas_cfg.get('offline_dir', SAS_OFFLINE_DIR))
        self.offline_app_jar   = os.path.join(self.offline_dir, 'app.jar')
        self.offline_agent_jar = os.path.join(self.offline_dir, 'jacocoagent.jar')
        self.offline_image_tar = os.path.join(self.offline_dir, 'sas-fuzz.image.tar.gz')
        self.offline_manifest  = os.path.join(self.offline_dir, 'MANIFEST.json')
        self.prefer_offline = bool(sas_cfg.get('prefer_offline', True))

        # Source acquisition — supports pre-staged tree, custom URL, mirror fallback
        self.source_dir_override = sas_cfg.get('source_dir')           # absolute/relative path to an existing tree
        self.source_url_override = sas_cfg.get('source_url')           # custom clone URL (mirror / SSH)
        self.source_branch = sas_cfg.get('source_branch', 'main')
        self.source_tarball_url = sas_cfg.get(
            'source_tarball_url',
            f"https://codeload.github.com/spring-projects/spring-authorization-server/tar.gz/refs/heads/{self.source_branch}"
        )

        # Build tuning — mirror URLs and timeouts for slow / blocked networks
        self.build_timeout = int(sas_cfg.get('build_timeout', 3600))          # seconds
        self.gradle_binary = sas_cfg.get('gradle_binary')                     # e.g. '/usr/bin/gradle'
        self.gradle_distribution_mirror = sas_cfg.get(
            'gradle_distribution_mirror',
            'https://mirrors.cloud.tencent.com/gradle'
        )
        self.maven_mirror = sas_cfg.get(
            'maven_mirror',
            'https://maven.aliyun.com/repository/public'
        )
        self.maven_spring_mirror = sas_cfg.get(
            'maven_spring_mirror',
            'https://maven.aliyun.com/repository/spring'
        )
        self.maven_plugin_mirror = sas_cfg.get(
            'maven_plugin_mirror',
            'https://maven.aliyun.com/repository/gradle-plugin'
        )
        self.use_mirrors = bool(sas_cfg.get('use_mirrors', True))

        # Standard endpoints (real — all exist)
        self.auth_endpoint       = f"{self.base_url}/oauth2/authorize"
        self.token_endpoint      = f"{self.base_url}/oauth2/token"
        self.introspect_endpoint = f"{self.base_url}/oauth2/introspect"
        self.revoke_endpoint     = f"{self.base_url}/oauth2/revoke"
        self.par_endpoint        = f"{self.base_url}/oauth2/par"
        self.userinfo_endpoint   = f"{self.base_url}/userinfo"
        self.jwks_endpoint       = f"{self.base_url}/oauth2/jwks"
        self.discovery_endpoint  = f"{self.base_url}/.well-known/openid-configuration"
        self.health_check_url    = self.discovery_endpoint

        # JaCoCo
        self.jacoco_enabled = sas_cfg.get('jacoco_enabled', True)
        self.jacoco = None
        if self.jacoco_enabled and JaCoCoManager:
            jacoco_cfg = config.get('jacoco', {})
            self.jacoco = JaCoCoManager(
                work_dir=jacoco_cfg.get('work_dir', 'jacoco_tools'),
                version=jacoco_cfg.get('version', '0.8.14'))

        # Eager reattach: when a fresh manager instance is created against an
        # already-running container (e.g. `--mode diagnose`, `--action status`),
        # repopulate JaCoCo classpaths from the live JAR so reports can be
        # generated without having to reinvoke start().  Guarded by a quick
        # existence probe so normal start()-then-prepare flow is untouched.
        if self.jacoco and self._container_running():
            try:
                self._prepare_classpaths()
            except Exception as e:
                print(f"[SAS] Eager classpath reattach skipped: {e}")

    # ── Lifecycle ──────────────────────────────────────────────────

    def start(self) -> bool:
        print("=" * 70)
        print("Starting Spring Authorization Server (SAS) — OAuth 2.1 + OIDC1")
        print(f"Source dir : {SAS_SOURCE_DIR}")
        print(f"Offline dir: {self.offline_dir}")
        print("=" * 70)

        self._cleanup_container()
        os.makedirs(self.work_dir, exist_ok=True)

        # Offline-first fast path — if a saved image or app.jar is shipped,
        # we SKIP clone / build entirely. Zero network access.
        offline_status = self._ensure_offline_bundle()
        if offline_status == 'image':
            # Docker image already loaded; go straight to startup
            if not self._start_container():
                return False
        elif offline_status == 'jar':
            # JAR staged; build Docker image locally, then start
            if not self._ensure_image_from_offline():
                return False
            if not self._start_container():
                return False
        else:
            # Fallback to the legacy network pipeline
            if not self._ensure_source():
                return False
            # Patch the demo app's hardcoded `messaging-client` so the fuzzer
            # can authenticate at /oauth2/token with CLIENT_SECRET_POST (the
            # default client_auth of protocol.base.token_exchange).  A source
            # change invalidates the cached JAR + Docker image so the next
            # _ensure_jar / _ensure_image produce a matching binary.
            if self._patch_messaging_client_for_fuzzer():
                self._invalidate_build_artifacts()
            if not self._ensure_jar():
                return False
            if not self._ensure_image():
                return False
            if not self._start_container():
                return False

        if not self._wait_ready():
            print("[SAS] Startup failed — container logs:")
            self._print_logs(tail=100)
            return False
        if self.jacoco:
            self._prepare_classpaths()
        return True

    def stop(self) -> None:
        # Only attempt a final JaCoCo dump when the container is actually
        # running AND the agent TCP port is reachable.  Otherwise the CLI
        # wastes ~10 s retrying a closed socket and prints a long
        # "Connection refused" stack trace that masks real errors.
        if self.jacoco:
            jp = int(self.config.get('jacoco', {}).get('agent_port', 6300))
            if self._container_running() and self._agent_port_reachable(port=jp):
                try:
                    self.jacoco.dump_coverage(port=jp)
                except Exception as e:
                    print(f"[SAS] Final JaCoCo dump raised: {e}")
            else:
                print(f"[SAS] Skipping final JaCoCo dump: "
                      f"container_running={self._container_running()}, "
                      f"agent_port_reachable={self._agent_port_reachable(port=jp)}")
        self._cleanup_container()

    def is_healthy(self) -> bool:
        try:
            r = requests.get(self.discovery_endpoint, timeout=5)
            return r.status_code == 200 and 'issuer' in r.text
        except Exception:
            return False

    # ── Source / Build ─────────────────────────────────────────────

    def _ensure_source(self) -> bool:
        global SAS_SOURCE_DIR

        # 0) Honour an explicit override: bind the module-level path to the user-supplied tree
        if self.source_dir_override:
            override = os.path.abspath(os.path.expanduser(self.source_dir_override))
            if os.path.isdir(os.path.join(override, self.sample_module)):
                SAS_SOURCE_DIR = override
                print(f"[SAS] Using pre-staged source: {override}")
                return True
            print(f"[SAS] source_dir override does not contain {self.sample_module}: {override}")
            return False

        # 1) Already cloned?
        if os.path.isdir(os.path.join(SAS_SOURCE_DIR, self.sample_module)):
            return True

        # 2) Try git clone across an ordered list of candidate URLs
        candidates: List[str] = []
        if self.source_url_override:
            candidates.append(self.source_url_override)
        candidates.extend([
            'https://github.com/spring-projects/spring-authorization-server.git',
            'https://ghproxy.com/https://github.com/spring-projects/spring-authorization-server.git',
            'https://gitee.com/mirrors/spring-authorization-server.git',
        ])

        parent = os.path.dirname(SAS_SOURCE_DIR) or '.'
        os.makedirs(parent, exist_ok=True)

        for url in candidates:
            if os.path.isdir(SAS_SOURCE_DIR):
                shutil.rmtree(SAS_SOURCE_DIR, ignore_errors=True)
            print(f"[SAS] Trying git clone: {url}")
            r = subprocess.run(
                ['git', '-c', 'http.postBuffer=524288000',
                       '-c', 'http.version=HTTP/1.1',
                       '-c', 'core.compression=0',
                 'clone', '--depth', '1', '-b', self.source_branch, url, SAS_SOURCE_DIR],
                capture_output=True, text=True)
            if r.returncode == 0 and os.path.isdir(os.path.join(SAS_SOURCE_DIR, self.sample_module)):
                print(f"[SAS] Clone succeeded from {url}")
                return True
            tail = (r.stderr or '').strip().splitlines()[-3:]
            print(f"[SAS]   failed: {' | '.join(tail)}")

        # 3) Tarball fallback (does not require git at all)
        print(f"[SAS] All git clones failed; falling back to tarball: {self.source_tarball_url}")
        try:
            if os.path.isdir(SAS_SOURCE_DIR):
                shutil.rmtree(SAS_SOURCE_DIR, ignore_errors=True)
            os.makedirs(SAS_SOURCE_DIR, exist_ok=True)
            with requests.get(self.source_tarball_url, stream=True, timeout=120) as resp:
                resp.raise_for_status()
                buf = io.BytesIO(resp.content)
            with tarfile.open(fileobj=buf, mode='r:gz') as tf:
                members = tf.getmembers()
                if not members:
                    raise RuntimeError("empty tarball")
                root = members[0].name.split('/', 1)[0]
                for m in members:
                    if not m.name.startswith(root + '/'):
                        continue
                    m.name = m.name[len(root) + 1:]
                    if m.name:
                        tf.extract(m, SAS_SOURCE_DIR)
            if os.path.isdir(os.path.join(SAS_SOURCE_DIR, self.sample_module)):
                print(f"[SAS] Tarball extracted into {SAS_SOURCE_DIR}")
                return True
            print("[SAS] Tarball extracted but sample module missing")
            return False
        except Exception as e:
            print(f"[SAS] Tarball fallback failed: {e}")
            print("[SAS] Manual recovery:")
            print("      1. Download the tarball with curl/wget on a machine with network access:")
            print(f"         curl -L -o sas.tar.gz '{self.source_tarball_url}'")
            print(f"      2. Extract it to: {SAS_SOURCE_DIR}")
            print(f"      3. Or set spring_authz.source_dir in the config to point to any local copy")
            return False

    def _ensure_jar(self) -> bool:
        sample_dir = os.path.join(SAS_SOURCE_DIR, self.sample_module)
        build_dir = os.path.join(sample_dir, 'build', 'libs')
        if os.path.isdir(build_dir):
            jars = [f for f in os.listdir(build_dir) if f.endswith('.jar') and 'plain' not in f]
            if jars:
                return True

        if self.use_mirrors:
            self._apply_build_mirrors()

        gradle_cmd, cwd = self._resolve_gradle_command()
        task = f':{self._resolve_gradle_project_name()}:bootJar'
        cmd = gradle_cmd + [task, '--stacktrace']

        print(f"[SAS] Building demo-authorizationserver: {' '.join(cmd)}")
        print(f"[SAS] Working dir : {cwd}")
        print(f"[SAS] Build timeout: {self.build_timeout}s (configurable via spring_authz.build_timeout)")

        try:
            # Stream output live so Gradle-wrapper download progress is visible
            proc = subprocess.Popen(cmd, cwd=cwd,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            start = time.time()
            last_heartbeat = start
            while True:
                if proc.poll() is not None:
                    break
                if time.time() - start > self.build_timeout:
                    proc.kill()
                    print(f"[SAS] Build timed out after {self.build_timeout}s")
                    self._print_build_help()
                    return False
                line = proc.stdout.readline()
                if line:
                    print(f"[gradle] {line.rstrip()}")
                    last_heartbeat = time.time()
                elif time.time() - last_heartbeat > 60:
                    # 1-minute silence — emit a progress ping so user sees we're alive
                    print(f"[SAS] …still building, elapsed {int(time.time() - start)}s")
                    last_heartbeat = time.time()
                else:
                    time.sleep(0.2)
            rc = proc.returncode
            if rc != 0:
                print(f"[SAS] Gradle build failed with exit {rc}")
                self._print_build_help()
                return False
            return True
        except Exception as e:
            print(f"[SAS] Build invocation error: {e}")
            return False

    def _resolve_gradle_command(self):
        """Prefer a user-configured system Gradle; otherwise use the wrapper."""
        if self.gradle_binary and os.path.isfile(self.gradle_binary):
            return [self.gradle_binary], SAS_SOURCE_DIR
        wrapper = os.path.join(SAS_SOURCE_DIR, 'gradlew')
        if os.path.exists(wrapper):
            os.chmod(wrapper, 0o755)
            return [wrapper], SAS_SOURCE_DIR
        return ['gradle'], SAS_SOURCE_DIR

    def _resolve_gradle_project_name(self) -> str:
        """
        Derive the Gradle project path for self.sample_module.

        SAS uses a non-standard settings.gradle that registers every non-
        `build.gradle` script as a FLAT project named after the script file
        (minus the `.gradle` extension).  For example:
            samples/demo-authorizationserver/samples-demo-authorizationserver.gradle
        is registered as `:samples-demo-authorizationserver`, NOT
        `:demo-authorizationserver` and NOT `:samples:demo-authorizationserver`.

        Allow explicit override via spring_authz.gradle_project; otherwise
        probe the sample directory for its actual build-script filename.
        """
        override = self.config.get('spring_authz', {}).get('gradle_project')
        if override:
            return override.lstrip(':')

        sample_dir = os.path.join(SAS_SOURCE_DIR, self.sample_module)
        if os.path.isdir(sample_dir):
            # Prefer flat-named scripts (SAS convention); fall back to build.gradle
            candidates = [f for f in os.listdir(sample_dir)
                          if f.endswith('.gradle') and f != 'build.gradle']
            if candidates:
                return candidates[0][:-len('.gradle')]
            if os.path.isfile(os.path.join(sample_dir, 'build.gradle')):
                # Standard layout → project path follows directory structure
                rel = self.sample_module.replace(os.sep, ':').strip(':')
                return rel

        # Last-resort fallback — original behavior
        return os.path.basename(self.sample_module)

    def _apply_build_mirrors(self) -> None:
        """Rewrite gradle-wrapper.properties, neutralize Develocity, drop init.gradle for Maven mirrors."""
        # 1) Patch gradle-wrapper distributionUrl
        wrapper_props = os.path.join(SAS_SOURCE_DIR, 'gradle', 'wrapper', 'gradle-wrapper.properties')
        if os.path.exists(wrapper_props):
            try:
                with open(wrapper_props, 'r') as f:
                    content = f.read()
                patched = content.replace(
                    'services.gradle.org/distributions',
                    self.gradle_distribution_mirror.replace('https://', '').replace('http://', '').rstrip('/')
                )
                if patched != content:
                    with open(wrapper_props, 'w') as f:
                        f.write(patched)
                    print(f"[SAS] Gradle wrapper mirrored → {self.gradle_distribution_mirror}")
            except Exception as e:
                print(f"[SAS] Could not patch gradle-wrapper.properties: {e}")

        # 1b) Neutralize Develocity/Build-Scan plugins so a fresh GRADLE_USER_HOME
        #     doesn't have to download them from gradlePluginPortal(), and so no
        #     traffic goes to ge.spring.io (which returned 403 here).
        self._patch_disable_develocity()

        # 2) Drop init.gradle into a project-local GRADLE_USER_HOME.
        #    Use Groovy (init.gradle) and `beforeSettings` so pluginManagement
        #    repositories are rewritten BEFORE settings.gradle is evaluated —
        #    `settingsEvaluated` runs too late for that purpose.
        gradle_user_home = os.path.join(self.work_dir, 'gradle-home')
        os.makedirs(gradle_user_home, exist_ok=True)
        # Remove any legacy Kotlin init script we may have created previously
        legacy = os.path.join(gradle_user_home, 'init.gradle.kts')
        if os.path.exists(legacy):
            try: os.remove(legacy)
            except Exception: pass
        init_script = os.path.join(gradle_user_home, 'init.gradle')
        init_content = f'''\
def central = "{self.maven_mirror}"
def spring  = "{self.maven_spring_mirror}"
def plugins = "{self.maven_plugin_mirror}"

// Rewrite pluginManagement BEFORE settings.gradle evaluates
beforeSettings {{ settings ->
    settings.pluginManagement {{
        repositories {{
            maven {{ url plugins }}
            maven {{ url central }}
            maven {{ url spring }}
            gradlePluginPortal()
        }}
    }}
    settings.dependencyResolutionManagement {{
        repositories {{
            maven {{ url central }}
            maven {{ url spring }}
            mavenCentral()
        }}
    }}
}}

// Also mirror every project's buildscript + runtime repositories
allprojects {{
    buildscript {{
        repositories {{
            mavenLocal()
            maven {{ url central }}
            maven {{ url spring }}
            maven {{ url plugins }}
        }}
    }}
    repositories {{
        mavenLocal()
        maven {{ url central }}
        maven {{ url spring }}
        maven {{ url plugins }}
    }}
}}
'''
        try:
            with open(init_script, 'w') as f:
                f.write(init_content)
            os.environ['GRADLE_USER_HOME'] = gradle_user_home
            print(f"[SAS] GRADLE_USER_HOME={gradle_user_home}  (Maven mirrors injected via beforeSettings)")
        except Exception as e:
            print(f"[SAS] Could not install init.gradle: {e}")

    def _patch_disable_develocity(self) -> None:
        """
        Remove every reference to the Develocity/Build-Scan plugin from BOTH
        settings.gradle (plugin declaration) AND build.gradle (the
        `develocity { buildScan { … } }` extension block).

        Rationale: on a fresh GRADLE_USER_HOME this plugin must be resolved
        from gradlePluginPortal and then calls ge.spring.io (403 in this
        environment). It only provides remote build-scan / cache features
        and is not required to produce the bootJar. Patches are idempotent
        via the `// [SAS-fuzz]` marker.
        """
        import re

        # ── settings.gradle — remove the plugin declaration ──
        settings_path = os.path.join(SAS_SOURCE_DIR, 'settings.gradle')
        if os.path.exists(settings_path):
            try:
                with open(settings_path, 'r') as f:
                    src = f.read()
                if '// [SAS-fuzz] develocity disabled' not in src:
                    patched = re.sub(
                        r'(?m)^(\s*)id\s+["\']io\.spring\.develocity\.conventions["\'](\s+version\s+["\'][^"\']+["\'])?\s*$',
                        r'\1// [SAS-fuzz] develocity disabled — \g<0>',
                        src
                    )
                    if patched != src:
                        with open(settings_path, 'w') as f:
                            f.write(patched)
                        print(f"[SAS] Patched settings.gradle — Develocity plugin disabled")
            except Exception as e:
                print(f"[SAS] Could not patch settings.gradle: {e}")

        # ── build.gradle — comment out the develocity { … } extension block ──
        build_path = os.path.join(SAS_SOURCE_DIR, 'build.gradle')
        if os.path.exists(build_path):
            try:
                with open(build_path, 'r') as f:
                    src = f.read()
                if '// [SAS-fuzz] develocity block disabled' in src:
                    return
                # Locate `develocity {` and find its matching closing brace.
                i = src.find('develocity')
                if i == -1:
                    return
                # Skip to the first `{` after `develocity`
                brace_open = src.find('{', i)
                if brace_open == -1:
                    return
                # Walk braces to find the matching close
                depth = 0
                end = -1
                for k in range(brace_open, len(src)):
                    c = src[k]
                    if c == '{':
                        depth += 1
                    elif c == '}':
                        depth -= 1
                        if depth == 0:
                            end = k
                            break
                if end == -1:
                    return
                block = src[i:end + 1]
                # Comment every line of the block with `//` prefix
                commented = '\n'.join(
                    '// ' + line if line.strip() else line
                    for line in block.splitlines()
                )
                patched = (
                    src[:i]
                    + '// [SAS-fuzz] develocity block disabled\n'
                    + commented
                    + src[end + 1:]
                )
                if patched != src:
                    with open(build_path, 'w') as f:
                        f.write(patched)
                    print(f"[SAS] Patched build.gradle — develocity extension neutralized")
            except Exception as e:
                print(f"[SAS] Could not patch build.gradle: {e}")

    def _print_build_help(self) -> None:
        print("[SAS] Build troubleshooting:")
        print("      • Increase  spring_authz.build_timeout  (current: "
              f"{self.build_timeout}s)")
        print("      • Verify mirrors are reachable:")
        print(f"          curl -I {self.gradle_distribution_mirror}/gradle-8.14-bin.zip")
        print(f"          curl -I {self.maven_mirror}/")
        print("      • Disable mirrors and use an HTTP/HTTPS proxy instead:")
        print("          \"spring_authz\": { \"use_mirrors\": false } ")
        print("          export HTTPS_PROXY=http://<proxy>:<port>")
        print("      • Or run the build manually once:")
        print(f"          cd {SAS_SOURCE_DIR} && ./gradlew "
              f":{self._resolve_gradle_project_name()}:bootJar --info")

    def _ensure_image(self) -> bool:
        """Build a Docker image with JaCoCo agent pre-installed."""
        chk = subprocess.run(['docker', 'image', 'inspect', self.image],
                             capture_output=True)
        if chk.returncode == 0:
            return True

        sample_dir = os.path.join(SAS_SOURCE_DIR, self.sample_module)
        build_dir = os.path.join(sample_dir, 'build', 'libs')
        jars = [f for f in os.listdir(build_dir) if f.endswith('.jar') and 'plain' not in f]
        if not jars:
            print("[SAS] No jar built")
            return False
        jar_file = os.path.join(build_dir, jars[0])

        # Download JaCoCo agent jar
        host_jacoco_dir = os.path.abspath(self.jacoco.work_dir) if self.jacoco else '/tmp/jacoco'
        agent_jar = os.path.join(host_jacoco_dir, 'jacocoagent.jar')
        if not os.path.exists(agent_jar) and self.jacoco:
            self.jacoco._download_if_needed()

        # Stage Dockerfile
        staging = os.path.join(self.work_dir, 'docker_stage')
        os.makedirs(staging, exist_ok=True)
        shutil.copy2(jar_file, os.path.join(staging, 'app.jar'))
        if os.path.exists(agent_jar):
            shutil.copy2(agent_jar, os.path.join(staging, 'jacocoagent.jar'))

        # File-based entrypoint with `set -f` to disable pathname expansion.
        # Without this, a `*` inside JAVA_OPTS (e.g. a JaCoCo includes pattern)
        # would be glob-expanded by the shell against the CWD before java sees it.
        entrypoint_sh = (
            "#!/bin/sh\n"
            "set -f\n"
            "# shellcheck disable=SC2086\n"
            "exec java $JAVA_OPTS -jar /app/app.jar\n"
        )
        with open(os.path.join(staging, 'entrypoint.sh'), 'w') as f:
            f.write(entrypoint_sh)

        dockerfile = """\
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY app.jar /app/app.jar
COPY jacocoagent.jar /opt/jacoco/jacocoagent.jar
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 9000 6300
ENTRYPOINT ["/entrypoint.sh"]
"""
        with open(os.path.join(staging, 'Dockerfile'), 'w') as f:
            f.write(dockerfile)

        r = subprocess.run(['docker', 'build', '-t', self.image, staging],
                           capture_output=False, text=True)
        return r.returncode == 0

    def _start_container(self) -> bool:
        host_jacoco_dir = os.path.abspath(self.jacoco.work_dir) if self.jacoco else '/tmp/jacoco'
        jacoco_cfg = self.config.get('jacoco', {})
        agent_port = jacoco_cfg.get('agent_port', 6300)

        # Coverage scope: Spring Authorization Server core + demo app
        includes = jacoco_cfg.get('includes', [
            'org.springframework.security.oauth2.server.authorization.*',
            'org.springframework.security.oauth2.core.*',
            'org.springframework.security.oauth2.jwt.*',
            'org.springframework.security.web.*',
            'sample.*',
        ])

        agent_opts = (
            f"output=tcpserver,address=0.0.0.0,port={agent_port},"
            f"includes={':'.join(includes)}"
        )
        agent_arg = f"-javaagent:/opt/jacoco/jacocoagent.jar={agent_opts}"

        jvm_opts = f"{agent_arg} -Xmx1024m"

        cmd = [
            'docker', 'run', '-d',
            '--name', self.container_name,
            '-p', f'{self.http_port}:9000',
            '-p', f'{agent_port}:{agent_port}',
            '-e', f'JAVA_OPTS={jvm_opts}',
            self.image,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[SAS] docker run failed: {r.stderr}")
            return False
        print(f"[SAS] Container started: {r.stdout.strip()}")
        return True

    def _wait_ready(self) -> bool:
        start = time.time()
        while time.time() - start < self.startup_timeout:
            try:
                r = requests.get(self.discovery_endpoint, timeout=3)
                if r.status_code == 200 and 'token_endpoint' in r.text:
                    print(f"[SAS] Ready at {self.base_url}")
                    return True
            except Exception:
                pass
            time.sleep(3)
        return False

    def _prepare_classpaths(self) -> None:
        """Extract BOOT-INF/classes and BOOT-INF/lib filtered to SAS jars."""
        if not self.jacoco:
            return
        lib_dir = os.path.join(os.path.abspath(self.jacoco.work_dir), 'sas_lib', 'extracted')
        os.makedirs(lib_dir, exist_ok=True)

        # Copy jar out of the container
        jar_copy = os.path.join(lib_dir, 'app.jar')
        subprocess.run(['docker', 'cp', f'{self.container_name}:/app/app.jar', jar_copy],
                       capture_output=True)
        if not os.path.exists(jar_copy):
            return

        classes_dir = os.path.join(lib_dir, 'classes')
        if os.path.exists(classes_dir):
            shutil.rmtree(classes_dir)
        os.makedirs(classes_dir, exist_ok=True)

        classpaths = []
        with zipfile.ZipFile(jar_copy, 'r') as zf:
            for name in zf.namelist():
                if name.startswith('BOOT-INF/classes/') and name.endswith('.class'):
                    rel = name[len('BOOT-INF/classes/'):]
                    if not rel:
                        continue
                    out = os.path.join(classes_dir, rel)
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    with zf.open(name) as src, open(out, 'wb') as dst:
                        dst.write(src.read())
        classpaths.append(classes_dir)

        target_jar_patterns = [
            'spring-security-oauth2-authorization-server',
            'spring-security-oauth2-core',
            'spring-security-oauth2-jose',
            'spring-security-web',
        ]
        jars_out = os.path.join(lib_dir, 'libs')
        os.makedirs(jars_out, exist_ok=True)
        with zipfile.ZipFile(jar_copy, 'r') as zf:
            for name in zf.namelist():
                if name.startswith('BOOT-INF/lib/') and name.endswith('.jar'):
                    bn = os.path.basename(name)
                    if any(p in bn for p in target_jar_patterns):
                        out = os.path.join(jars_out, bn)
                        with zf.open(name) as src, open(out, 'wb') as dst:
                            dst.write(src.read())
                        classpaths.append(out)

        self.jacoco.set_classpaths(classpaths)
        print(f"[SAS] JaCoCo classpaths ready: {len(classpaths)}")

    def _cleanup_container(self) -> None:
        subprocess.run(['docker', 'rm', '-f', self.container_name], capture_output=True)

    def _patch_messaging_client_for_fuzzer(self) -> bool:
        """Add CLIENT_SECRET_POST to the demo app's messaging-client.

        Without this, /oauth2/token rejects the default body-based
        client authentication used by protocol.base.token_exchange()
        with 401 invalid_client.  Idempotent via a `// [SAS-fuzz]` marker.
        Returns True iff the file was modified (caller should invalidate
        any cached build artifacts).
        """
        import re
        src_path = os.path.join(
            SAS_SOURCE_DIR, self.sample_module,
            'src', 'main', 'java', 'sample', 'config',
            'AuthorizationServerConfig.java')
        if not os.path.isfile(src_path):
            print(f"[SAS] AuthorizationServerConfig.java not found at {src_path}; "
                  f"skipping messaging-client patch")
            return False
        try:
            with open(src_path, 'r') as f:
                src = f.read()
        except Exception as e:
            print(f"[SAS] Could not read AuthorizationServerConfig.java: {e}")
            return False
        if '// [SAS-fuzz] messaging-client POST auth enabled' in src:
            return False

        # Insert CLIENT_SECRET_POST after the messaging-client's BASIC line.
        # messaging-client is identified by being immediately followed by
        # AUTHORIZATION_CODE grant type — the other CLIENT_SECRET_BASIC
        # registration (token-client) is followed by token-exchange instead.
        pattern = re.compile(
            r'(\.clientAuthenticationMethod\(ClientAuthenticationMethod\.CLIENT_SECRET_BASIC\))'
            r'(\s*\.authorizationGrantType\(AuthorizationGrantType\.AUTHORIZATION_CODE\))'
        )
        replacement = (
            r'\1'
            '\n\t\t\t\t// [SAS-fuzz] messaging-client POST auth enabled\n'
            '\t\t\t\t.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)'
            r'\2'
        )
        patched, n = pattern.subn(replacement, src, count=1)
        if n == 0:
            print("[SAS] messaging-client patch pattern did not match — "
                  "demo source layout may have changed; leaving file as-is")
            return False
        try:
            with open(src_path, 'w') as f:
                f.write(patched)
        except Exception as e:
            print(f"[SAS] Could not write AuthorizationServerConfig.java: {e}")
            return False
        print("[SAS] Patched AuthorizationServerConfig.java — "
              "messaging-client now accepts CLIENT_SECRET_POST")
        return True

    def _invalidate_build_artifacts(self) -> None:
        """Drop any cached JAR and Docker image so a changed source rebuilds.

        Invoked after _patch_messaging_client_for_fuzzer() reports a change.
        Without this, _ensure_jar / _ensure_image short-circuit on their
        existence checks and we keep running the un-patched binary.
        """
        sample_dir = os.path.join(SAS_SOURCE_DIR, self.sample_module)
        build_dir = os.path.join(sample_dir, 'build', 'libs')
        if os.path.isdir(build_dir):
            shutil.rmtree(build_dir, ignore_errors=True)
            print(f"[SAS] Cleared stale build output at {build_dir}")
        # Also drop any cached Gradle build state for this module so
        # bootJar actually re-runs (not UP-TO-DATE).
        cache_dir = os.path.join(sample_dir, 'build')
        if os.path.isdir(cache_dir):
            shutil.rmtree(cache_dir, ignore_errors=True)
        r = subprocess.run(['docker', 'image', 'rm', '-f', self.image],
                           capture_output=True, text=True)
        if r.returncode == 0:
            print(f"[SAS] Removed stale Docker image {self.image}")

    def _container_running(self) -> bool:
        """True iff `docker inspect` reports the container as .State.Running."""
        try:
            r = subprocess.run(
                ['docker', 'inspect', '-f', '{{.State.Running}}', self.container_name],
                capture_output=True, text=True, timeout=5)
            return r.returncode == 0 and r.stdout.strip().lower() == 'true'
        except Exception:
            return False

    def _agent_port_reachable(self, host: str = '127.0.0.1',
                              port: int = 6300, timeout: float = 1.0) -> bool:
        """Quick TCP probe of the JaCoCo tcpserver agent."""
        import socket
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except OSError:
            return False

    def _print_logs(self, tail: int = 100) -> None:
        r = subprocess.run(['docker', 'logs', '--tail', str(tail), self.container_name],
                           capture_output=True, text=True)
        print(r.stdout)
        print(r.stderr)

    # ── Offline bundle ─────────────────────────────────────────────

    def _ensure_offline_bundle(self) -> str:
        """Try to satisfy deployment from the vendored bundle.

        Returns:
            'image' → Docker image loaded from tarball; nothing else to do
            'jar'   → JAR staged; caller must build Docker image from it
            ''      → no usable offline artifacts; fall through to network path
        """
        if not self.prefer_offline:
            return ''
        if not os.path.isdir(self.offline_dir):
            print(f"[SAS] No offline bundle at {self.offline_dir}; will try network path")
            return ''

        self._load_offline_manifest()

        # 1) Pre-saved Docker image — the strongest offline form
        if os.path.isfile(self.offline_image_tar):
            print(f"[SAS] Loading Docker image from {self.offline_image_tar}")
            try:
                with open(self.offline_image_tar, 'rb') as f:
                    subprocess.run(['docker', 'load'], stdin=f, check=True,
                                   capture_output=True)
                chk = subprocess.run(['docker', 'image', 'inspect', self.image],
                                     capture_output=True)
                if chk.returncode == 0:
                    print(f"[SAS] Image {self.image} ready (offline)")
                    return 'image'
                print(f"[SAS] WARN image {self.image} not found after docker load")
            except Exception as e:
                print(f"[SAS] docker load failed: {e}")

        # 2) Pre-built fat JAR — stage it into the expected build/libs layout
        if os.path.isfile(self.offline_app_jar):
            sample_build_libs = os.path.join(
                SAS_SOURCE_DIR, self.sample_module, 'build', 'libs')
            os.makedirs(sample_build_libs, exist_ok=True)
            staged = os.path.join(sample_build_libs, 'demo-authorizationserver.jar')
            if not os.path.exists(staged) or (
                os.path.getsize(staged) != os.path.getsize(self.offline_app_jar)
            ):
                shutil.copy2(self.offline_app_jar, staged)
            print(f"[SAS] Staged offline JAR → {staged}")

            # JaCoCo agent: prefer the vendored copy so JaCoCoManager doesn't
            # have to hit the internet either
            if self.jacoco and os.path.isfile(self.offline_agent_jar):
                target_agent = os.path.join(
                    os.path.abspath(self.jacoco.work_dir), 'jacocoagent.jar')
                os.makedirs(os.path.dirname(target_agent), exist_ok=True)
                if not os.path.exists(target_agent) or (
                    os.path.getsize(target_agent)
                    != os.path.getsize(self.offline_agent_jar)
                ):
                    shutil.copy2(self.offline_agent_jar, target_agent)
                print(f"[SAS] Staged offline JaCoCo agent → {target_agent}")
            return 'jar'

        print(f"[SAS] No offline artifacts found in {self.offline_dir}")
        return ''

    def _ensure_image_from_offline(self) -> bool:
        """Build the Docker image using only the staged offline JAR (no source tree).

        Identical Dockerfile layout to _ensure_image(), but sourced exclusively
        from self.offline_dir so no clone / no gradle / no maven is needed.
        """
        chk = subprocess.run(['docker', 'image', 'inspect', self.image],
                             capture_output=True)
        if chk.returncode == 0:
            return True

        staging = os.path.join(self.work_dir, 'docker_stage')
        os.makedirs(staging, exist_ok=True)
        shutil.copy2(self.offline_app_jar, os.path.join(staging, 'app.jar'))
        if os.path.isfile(self.offline_agent_jar):
            shutil.copy2(self.offline_agent_jar,
                         os.path.join(staging, 'jacocoagent.jar'))
        else:
            # Create an empty file so COPY in the Dockerfile doesn't fail
            open(os.path.join(staging, 'jacocoagent.jar'), 'wb').close()

        entrypoint_sh = (
            "#!/bin/sh\n"
            "set -f\n"
            "# shellcheck disable=SC2086\n"
            "exec java $JAVA_OPTS -jar /app/app.jar\n"
        )
        with open(os.path.join(staging, 'entrypoint.sh'), 'w') as f:
            f.write(entrypoint_sh)

        dockerfile = """\
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY app.jar /app/app.jar
COPY jacocoagent.jar /opt/jacoco/jacocoagent.jar
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 9000 6300
ENTRYPOINT ["/entrypoint.sh"]
"""
        with open(os.path.join(staging, 'Dockerfile'), 'w') as f:
            f.write(dockerfile)

        print(f"[SAS] Building Docker image {self.image} from offline JAR ...")
        r = subprocess.run(['docker', 'build', '-t', self.image, staging],
                           capture_output=False, text=True)
        return r.returncode == 0

    def _load_offline_manifest(self) -> None:
        """Optional integrity check against bundled MANIFEST.json."""
        if not os.path.isfile(self.offline_manifest):
            return
        try:
            with open(self.offline_manifest) as f:
                manifest = json.load(f)
        except Exception as e:
            print(f"[SAS] MANIFEST.json unreadable: {e}")
            return
        for key, expected in (manifest.get('sha256') or {}).items():
            path = os.path.join(self.offline_dir, key)
            if not os.path.isfile(path):
                continue
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
            actual = h.hexdigest()
            status = 'OK ' if actual == expected else 'WARN'
            print(f"[SAS] sha256 {status} {key}: {actual[:12]}… "
                  f"(expected {expected[:12]}…)")

    # ── Offline bundle producer (run on a networked host) ──────────

    def package_offline_bundle(self, include_image: bool = True) -> bool:
        """Generate the portable bundle from the current built state.

        Precondition: app JAR has been built (./gradlew :<sample>:bootJar).
        Run this once on a networked host, then commit spring_authz_offline/
        (or mirror it by any other means) so every other machine can deploy
        with zero network access.
        """
        os.makedirs(self.offline_dir, exist_ok=True)
        manifest = {'image': self.image, 'sha256': {}}

        # 1) Copy the fat JAR produced by Gradle
        sample_dir = os.path.join(SAS_SOURCE_DIR, self.sample_module)
        build_dir = os.path.join(sample_dir, 'build', 'libs')
        if not os.path.isdir(build_dir):
            print(f"[SAS] Build output not found: {build_dir}")
            print(f"[SAS] Run ./gradlew :{self._resolve_gradle_project_name()}:bootJar first")
            return False
        jars = [f for f in os.listdir(build_dir)
                if f.endswith('.jar') and 'plain' not in f]
        if not jars:
            print("[SAS] No non-plain JAR in build/libs")
            return False
        src_jar = os.path.join(build_dir, jars[0])
        shutil.copy2(src_jar, self.offline_app_jar)
        manifest['sha256']['app.jar'] = self._sha256(self.offline_app_jar)
        print(f"[SAS] Packaged JAR → {self.offline_app_jar}")

        # 2) Copy the JaCoCo agent
        if self.jacoco:
            agent_src = os.path.join(
                os.path.abspath(self.jacoco.work_dir), 'jacocoagent.jar')
            if not os.path.exists(agent_src):
                try:
                    self.jacoco._download_if_needed()
                except Exception as e:
                    print(f"[SAS] JaCoCo agent download failed: {e}")
            if os.path.exists(agent_src):
                shutil.copy2(agent_src, self.offline_agent_jar)
                manifest['sha256']['jacocoagent.jar'] = self._sha256(
                    self.offline_agent_jar)
                print(f"[SAS] Packaged JaCoCo agent → {self.offline_agent_jar}")

        # 3) Optionally save the Docker image as the strongest offline form
        if include_image:
            # Ensure the image exists locally first
            chk = subprocess.run(['docker', 'image', 'inspect', self.image],
                                 capture_output=True)
            if chk.returncode != 0:
                print(f"[SAS] Image {self.image} not found locally; building it")
                if not self._ensure_image_from_offline():
                    print("[SAS] Image build failed; skipping tarball")
                    include_image = False
            if include_image:
                print(f"[SAS] Saving Docker image → {self.offline_image_tar}")
                save = subprocess.Popen(['docker', 'save', self.image],
                                        stdout=subprocess.PIPE)
                import gzip
                with gzip.open(self.offline_image_tar, 'wb',
                               compresslevel=6) as gz:
                    while True:
                        chunk = save.stdout.read(1 << 20)
                        if not chunk:
                            break
                        gz.write(chunk)
                save.wait()
                if save.returncode == 0:
                    manifest['sha256']['sas-fuzz.image.tar.gz'] = self._sha256(
                        self.offline_image_tar)
                    print(f"[SAS] Image tarball ready")
                else:
                    print("[SAS] docker save failed")

        # 4) MANIFEST.json
        manifest['version'] = {
            'spring_authz_manager': '1.0',
            'generated_at': int(time.time()),
        }
        with open(self.offline_manifest, 'w') as f:
            json.dump(manifest, f, indent=2)
        print(f"[SAS] MANIFEST.json written")
        return True

    @staticmethod
    def _sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                h.update(chunk)
        return h.hexdigest()


def create_test_config_spring_authz() -> str:
    config = {
        "name": "oauth-spring-authz-fuzzer",
        "target_type": "spring_authz",
        "protocol": "OAUTH",
        "implementation": "Spring Authorization Server",
        "output_dir": "out/oauth_sas_coverage",
        "oauth": {
            "base_url": "http://127.0.0.1:9000",
            "realm": "",
            "client_id": "messaging-client",
            "client_secret": "secret",
            "redirect_uri": "http://127.0.0.1:8080/authorized",
            "user": "user1",
            "password": "password",
            "scope": "openid profile message.read message.write"
        },
        "spring_authz": {
            "container_name": "sas-fuzz",
            "image": "sas-fuzz:latest",
            "http_port": 9000,
            "work_dir": "./sas_work",
            "startup_timeout": 180,
            "jacoco_enabled": True,
            "sample_module": "samples/demo-authorizationserver"
        },
        "jacoco": {
            "version": "0.8.14",
            "work_dir": "jacoco_tools",
            "agent_port": 6300,
            "dump_every_n": 50,
            "includes": [
                "org.springframework.security.oauth2.server.authorization.*",
                "org.springframework.security.oauth2.core.*",
                "org.springframework.security.oauth2.jwt.*",
                "org.springframework.security.web.*",
                "sample.*"
            ]
        },
        "fuzzing": {
            "max_iterations": 4000,
            "timeout_seconds": 14400,
            "differential_coverage": True,
            "baseline_refresh_every": 25,
            "coverage_cache_ttl": 15,
            "canonicalize_sequences": True
        }
    }
    os.makedirs("configs", exist_ok=True)
    path = "configs/oauth_spring_authz.json"
    with open(path, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"[SAS] Created config: {path}")
    return path


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--config', default='configs/oauth_spring_authz.json')
    p.add_argument('--action',
                   choices=['start', 'stop', 'status', 'init-config',
                            'package-offline'],
                   default='start')
    p.add_argument('--no-image', action='store_true',
                   help='when package-offline: skip the Docker image tarball '
                        '(~210 MB) and only ship the JAR')
    args = p.parse_args()
    if args.action == 'init-config':
        create_test_config_spring_authz(); raise SystemExit(0)
    if not os.path.exists(args.config):
        create_test_config_spring_authz()
    with open(args.config) as f:
        cfg = json.load(f)
    m = SpringAuthzManager(cfg)
    if args.action == 'start':
        raise SystemExit(0 if m.start() else 1)
    if args.action == 'stop':
        m.stop()
    if args.action == 'status':
        print("healthy" if m.is_healthy() else "unhealthy")
    if args.action == 'package-offline':
        raise SystemExit(0 if m.package_offline_bundle(
            include_image=not args.no_image) else 1)