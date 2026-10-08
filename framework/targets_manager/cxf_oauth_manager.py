#!/usr/bin/env python3
"""
Apache CXF rs-security-oauth2 Manager

Target: https://github.com/apache/cxf (rt/rs/security/sso/oauth2,
        rt/rs/security/oauth-parent)

Builds and runs the official CXF JAX-RS OAuth2 sample (distribution/src/main/release/samples/jax_rs/big_query).
The canonical fuzzing target is distribution/src/main/release/samples/jax_rs/oauth2:
    - /services/oauth2/authorize     (AuthorizationCodeGrant)
    - /services/oauth2/token         (TokenService)
    - /services/oauth2/introspect    (TokenIntrospectionService)
    - /services/oauth2/revoke        (TokenRevocationService)
    - /services/oidc/userinfo
    - /services/oidc/idp/.well-known/openid-configuration

CVE refs:
    - CVE-2022-46364, CVE-2020-13954, CVE-2019-12406,
    - CVE-2018-8039 (TLS hostname verification), CVE-2021-22696 (JWT filter bypass)
"""

import os
import json
import shutil
import zipfile
import subprocess
import time
from typing import Dict, List, Optional

import requests

try:
    from core.coverage import JaCoCoManager
except ImportError:
    JaCoCoManager = None

from targets_manager.base import TargetManager

from core.paths import PROJECT_ROOT

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CXF_SOURCE_DIR = os.path.join(SCRIPT_DIR, 'cxf')


class CxfOAuthManager(TargetManager):
    """Apache CXF rs-security-oauth2 manager."""

    def __init__(self, config: Dict):
        # base __init__ initializes _atexit_registered (register_cleanup crashes
        # with AttributeError without it when driven via run_oauth_fuzzing.py)
        super().__init__(config)
        self.config = config
        cxf_cfg = config.get('cxf_oauth', {})
        oauth_cfg = config.get('oauth', {})

        self.base_url = oauth_cfg.get('base_url', 'http://127.0.0.1:8081')
        self.container_name = cxf_cfg.get('container_name', 'cxf-oauth-fuzz')
        self.image = cxf_cfg.get('image', 'cxf-oauth:latest')
        self.http_port = cxf_cfg.get('http_port', 8081)
        self.config_dir = os.path.abspath(cxf_cfg.get('config_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'cxf_service', 'config')))
        self.work_dir = os.path.abspath(cxf_cfg.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'cxf_service', 'work')))
        self.startup_timeout = cxf_cfg.get('startup_timeout', 120)

        # Offline bundle support (mirrors spring_authz_manager pattern)
        self.prefer_offline = bool(cxf_cfg.get('prefer_offline', True))
        self.offline_dir = os.path.abspath(
            cxf_cfg.get('offline_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'cxf_service', 'cxf_offline')))
        self.offline_war = os.path.join(self.offline_dir, 'oauth.war')
        self.offline_agent_jar = os.path.join(self.offline_dir, 'jacocoagent.jar')
        # Sample sub-path within CXF source tree; overridable for tree-shape drift.
        self.sample_path = cxf_cfg.get(
            'sample_path',
            os.path.join('distribution', 'src', 'main', 'release',
                         'samples', 'jax_rs', 'oauth2'))

        self.auth_endpoint       = f"{self.base_url}/services/oauth2/authorize"
        self.token_endpoint      = f"{self.base_url}/services/oauth2/token"
        self.introspect_endpoint = f"{self.base_url}/services/oauth2/introspect"
        self.revoke_endpoint     = f"{self.base_url}/services/oauth2/revoke"
        self.userinfo_endpoint   = f"{self.base_url}/services/oidc/userinfo"
        self.jwks_endpoint       = f"{self.base_url}/services/oidc/jwk"
        self.discovery_endpoint  = f"{self.base_url}/services/oidc/.well-known/openid-configuration"
        self.health_check_url    = f"{self.base_url}/services"

        self.jacoco_enabled = cxf_cfg.get('jacoco_enabled', True)
        self.jacoco = None
        if self.jacoco_enabled and JaCoCoManager:
            jacoco_cfg = config.get('jacoco', {})
            self.jacoco = JaCoCoManager(
                work_dir=jacoco_cfg.get('work_dir', 'jacoco_tools'),
                version=jacoco_cfg.get('version', '0.8.14'))

        # Eager classpath reattach for --mode diagnose / --action status against
        # an already-running container. Identical rationale to SAS fix.
        if self.jacoco and self._container_running():
            try:
                self._prepare_classpaths()
            except Exception as e:
                print(f"[CXF] Eager classpath reattach skipped: {e}")

    def _container_running(self) -> bool:
        r = subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Running}}', self.container_name],
            capture_output=True, text=True)
        return r.returncode == 0 and r.stdout.strip() == 'true'

    def start(self) -> bool:
        print("=" * 70)
        print("Starting Apache CXF rs-security-oauth2 sample")
        print(f"Offline dir: {self.offline_dir}")
        print("=" * 70)
        self._cleanup_container()
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)

        # Docker-first readiness detection — any of these three signals is
        # sufficient to proceed directly to `_ensure_image()`:
        #   (a) Multi-stage Docker source tree at offline_dir/source/pom.xml
        #       → Maven runs INSIDE the Docker build (preferred).
        #   (b) Pre-built WAR at offline_dir/oauth.war
        #       → single-stage Dockerfile stages it onto Tomcat.
        #   (c) Pre-existing Docker image already in the local registry
        #       → `_ensure_image()` returns immediately via `docker image inspect`.
        multistage_src = os.path.isfile(
            os.path.join(self.offline_dir, 'source', 'pom.xml'))
        prebuilt_war = os.path.isfile(self.offline_war)
        img_cached = subprocess.run(
            ['docker', 'image', 'inspect', self.image],
            capture_output=True).returncode == 0

        if multistage_src:
            print(f"[CXF] Using multi-stage Docker source: "
                  f"{os.path.join(self.offline_dir, 'source')}")
        elif prebuilt_war:
            print(f"[CXF] Using offline WAR: {self.offline_war}")
        elif img_cached:
            print(f"[CXF] Reusing cached Docker image: {self.image}")
        else:
            # Only fall through to the legacy clone+mvn path if none of the
            # Docker-first sources exist. This branch is the one that failed
            # in the terminal output.
            if not self._ensure_cxf_source():
                print("[CXF] No Docker-first source available:")
                print(f"      • multi-stage project at {self.offline_dir}/source/pom.xml  (preferred)")
                print(f"      • pre-built WAR at      {self.offline_war}")
                print(f"      • cached Docker image   {self.image}")
                print("      • network clone of https://github.com/apache/cxf.git")
                return False
            if not self._ensure_bundle():
                print("[CXF] Bundle build failed; stage a pre-built WAR at "
                      f"{self.offline_war} and retry with prefer_offline=true")
                return False

        if not self._ensure_image():
            return False
        if not self._start_container():
            return False
        if not self._wait_ready():
            self._print_logs()
            return False
        if self.jacoco:
            self._prepare_classpaths()
        print(f"[CXF] Ready at {self.base_url}")
        return True

    def stop(self) -> None:
        # Only attempt a JaCoCo dump if the container + agent are still alive;
        # otherwise the subprocess emits 10 "Connection refused" lines that
        # drown the log and serve no purpose (same defect pattern as SAS had).
        if self.jacoco and self._container_running():
            try:
                jp = self.config.get('jacoco', {}).get('agent_port', 6300)
                if self._agent_reachable(port=jp):
                    self.jacoco.dump_coverage(port=jp)
            except Exception:
                pass
        self._cleanup_container()

    def _agent_reachable(self, port: int, timeout: float = 1.0) -> bool:
        import socket
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=timeout):
                return True
        except Exception:
            return False

    def is_healthy(self) -> bool:
        """Strict deployment probe.

        Accept codes that prove routing is live:
          * 200 / 302 on /services              → CXFServlet mounted
          * 400 / 401 / 302 on /oauth2/authorize → jaxrs:server bound
        Reject 404 (context load failed) and 500 (runtime error inside
        the app).  The caller will dump docker logs after a few
        consecutive 5xx so the real stack trace surfaces without a
        silent 3-minute wait.
        """
        for url, accept in (
            (f"{self.base_url}/services",                   (200, 302)),
            (f"{self.base_url}/services/oauth2/authorize",  (400, 401, 302)),
        ):
            try:
                r = requests.get(url, timeout=5, allow_redirects=False)
                if r.status_code in accept:
                    return True
            except Exception:
                continue
        return False

    def _probe_status(self) -> Optional[int]:
        try:
            r = requests.get(f"{self.base_url}/services",
                             timeout=5, allow_redirects=False)
            return r.status_code
        except Exception:
            return None

    def _wait_ready(self) -> bool:
        start = time.time()
        consecutive_5xx = 0
        consecutive_404 = 0
        while time.time() - start < self.startup_timeout:
            if self.is_healthy():
                return True
            status = self._probe_status()
            if status and 500 <= status < 600:
                consecutive_5xx += 1
                if consecutive_5xx >= 3:
                    print(f"[CXF] Server replied {status} on 3 consecutive "
                          f"probes — deployment is broken, dumping logs:")
                    try:
                        subprocess.run(
                            ['docker', 'logs', '--tail', '120',
                             self.container_name],
                            check=False)
                    except Exception:
                        pass
                    return False
            elif status == 404:
                consecutive_404 += 1
                # Sustained 404 means Tomcat marked the ROOT webapp
                # FAILED (e.g. bean-wiring NoClassDefFoundError).
                # After 10 probes (~30 s) dump logs instead of
                # waiting out the full startup_timeout.
                if consecutive_404 >= 10:
                    print(f"[CXF] Server replied 404 on 10 consecutive "
                          f"probes — webapp context did not start, "
                          f"dumping logs:")
                    try:
                        subprocess.run(
                            ['docker', 'logs', '--tail', '200',
                             self.container_name],
                            check=False)
                    except Exception:
                        pass
                    return False
            else:
                consecutive_5xx = 0
                consecutive_404 = 0
            elapsed = int(time.time() - start)
            if elapsed and elapsed % 15 == 0:
                print(f"[CXF] Waiting for deployment ({elapsed}s, last={status}) ...")
            time.sleep(3)
        return False

    def _ensure_cxf_source(self) -> bool:
        if os.path.isdir(CXF_SOURCE_DIR):
            return True
        print(f"[CXF] Cloning CXF source tree (~200MB) to {CXF_SOURCE_DIR}")
        r = subprocess.run([
            'git', 'clone', '--depth', '1',
            'https://github.com/apache/cxf.git', CXF_SOURCE_DIR
        ], capture_output=True, text=True)
        return r.returncode == 0

    def _ensure_bundle(self) -> bool:
        """Build the rs-security-oauth2 bundle + JAX-RS sample.

        Offline-first: when a pre-built WAR exists in offline_dir, skip the
        git clone + mvn steps entirely.
        """
        if self.prefer_offline and os.path.isfile(self.offline_war):
            print(f"[CXF] Using offline WAR: {self.offline_war}")
            return True

        if not self._ensure_cxf_source():
            return False

        sample_dir = os.path.join(CXF_SOURCE_DIR, self.sample_path)
        if not os.path.isdir(sample_dir):
            # Tree-shape fallback: try the classic oauth-parent location
            sample_dir = os.path.join(CXF_SOURCE_DIR, 'rt', 'rs', 'security', 'oauth-parent')
        if not os.path.isdir(sample_dir):
            print(f"[CXF] Sample dir not found under {CXF_SOURCE_DIR}")
            return False

        war_target = os.path.join(sample_dir, 'target')
        if os.path.isdir(war_target):
            wars = [f for f in os.listdir(war_target) if f.endswith('.war')]
            if wars:
                return True

        print("[CXF] Building with Maven (~10 min first time)...")
        r = subprocess.run(
            ['mvn', '-pl',
             'rt/rs/security/sso/oauth2,rt/rs/security/oauth-parent',
             '-am', 'package', '-DskipTests', '-q'],
            cwd=CXF_SOURCE_DIR, capture_output=False, timeout=1800)
        return r.returncode == 0

    def _stage_jacoco_agent(self, dest_dir: str) -> bool:
        """Copy jacocoagent.jar into dest_dir so Docker COPY can find it.

        JaCoCoManager.__init__ already invokes _download_and_extract_tools()
        during construction, so the agent jar should always be present under
        work_dir. We only need to locate + copy it here; if for any reason
        the jar is missing we try a one-shot re-extraction and then create
        an empty placeholder as a last resort so `docker build` doesn't fail
        on the COPY directive.
        """
        if not self.jacoco:
            open(os.path.join(dest_dir, 'jacocoagent.jar'), 'wb').close()
            return False

        agent_src = os.path.join(os.path.abspath(self.jacoco.work_dir),
                                 'jacocoagent.jar')
        if not os.path.isfile(agent_src):
            # Re-run the public bootstrap path. The method name is
            # _download_and_extract_tools (NOT _download_if_needed — that
            # was a typo in an earlier patch).
            try:
                self.jacoco._download_and_extract_tools()
            except Exception as e:
                print(f"[CXF] JaCoCo agent re-extraction failed: {e}")

        if os.path.isfile(agent_src):
            shutil.copy2(agent_src, os.path.join(dest_dir, 'jacocoagent.jar'))
            return True

        # Last-resort: empty placeholder so the Dockerfile COPY does not
        # break the build; the container will run WITHOUT coverage until the
        # jar is staged manually.
        print(f"[CXF] WARNING: jacocoagent.jar not found at {agent_src}; "
              "coverage will be disabled for this image")
        open(os.path.join(dest_dir, 'jacocoagent.jar'), 'wb').close()
        return False

    def _ensure_image(self) -> bool:
        """Ensure the CXF OAuth image is (re)built and ready to run.

        We deliberately DO NOT early-return just because the tag exists
        locally: that pattern silently served a stale image after source
        edits (Dockerfile / web.xml / *.java), causing the container to
        still deploy `services.war` with no MockAuthFilter and every
        endpoint to 404.

        Instead we rely on BuildKit's content-addressable layer cache —
        a no-op rebuild is O(1s), and any actual source change correctly
        invalidates only the affected layer.  A user can opt back into
        the old behaviour with `cxf_oauth.reuse_image: true` in the
        config (useful for offline dev loops).

        Docker-first workflow: multi-stage Dockerfile under
        `targets_manager/cxf_offline/source/` runs Maven inside a builder
        image to produce `oauth.war`, then stages it onto Tomcat with the
        JaCoCo agent.  Host needs only Docker — no JDK, no Maven, no
        pre-built WAR.

        Fallback: if a pre-built WAR exists at `offline_dir/oauth.war`,
        use the simpler single-stage Dockerfile from the earlier flow.
        """
        cxf_cfg = self.config.get('cxf_oauth', {})
        reuse_image = bool(cxf_cfg.get('reuse_image', False))
        if reuse_image:
            chk = subprocess.run(['docker', 'image', 'inspect', self.image],
                                 capture_output=True)
            if chk.returncode == 0:
                print(f"[CXF] reuse_image=true; skipping rebuild of {self.image}")
                return True

        source_dir = os.path.join(self.offline_dir, 'source')
        has_source = os.path.isfile(os.path.join(source_dir, 'pom.xml'))

        if has_source:
            # Stage the JaCoCo agent + entrypoint.sh next to the Dockerfile
            # so the multi-stage build can COPY them in stage 2.
            self._stage_jacoco_agent(source_dir)

            entrypoint_sh = (
                "#!/bin/sh\n"
                "set -f\n"
                "# shellcheck disable=SC2086\n"
                "export CATALINA_OPTS=\"$JACOCO_OPTS $CATALINA_OPTS\"\n"
                "exec /usr/local/tomcat/bin/catalina.sh run\n"
            )
            with open(os.path.join(source_dir, 'entrypoint.sh'), 'w') as f:
                f.write(entrypoint_sh)

            # Pre-pull the base images BEFORE `docker build` runs so a 429
            # from one mirror doesn't kill the whole build — we can retry
            # the pull across multiple fully-qualified registry paths and
            # the build then finds the image already cached.
            base_registry = self._prepull_base_images([
                'maven:3.9-eclipse-temurin-11',
                'tomcat:9-jre11',
            ])
            if base_registry is None:
                print("[CXF] Could not pull base images from any registry; "
                      "check Docker daemon mirrors and retry")
                return False

            print(f"[CXF] Building Docker image {self.image} "
                  f"from multi-stage source at {source_dir} "
                  f"(BASE_REGISTRY={base_registry}) ...")

            # Enable BuildKit + inline cache so re-builds after
            # `docker image rm -f` still reuse the Maven dependency layer
            # and the Tomcat/Temurin base images. `--progress=plain` keeps
            # the log grep-friendly for CI.
            env = os.environ.copy()
            env['DOCKER_BUILDKIT'] = '1'

            cmd = ['docker', 'build',
                   '--progress=plain',
                   '--build-arg', 'BUILDKIT_INLINE_CACHE=1',
                   '--build-arg', f'BASE_REGISTRY={base_registry}']

            # Only add --cache-from when the image already exists locally.
            # On a clean first build the cache reference would be resolved
            # against the configured Docker Hub mirrors, which (a) is wasted
            # network and (b) triggered the 429 from xuanyuan.me observed in
            # the previous run. After the first successful build the local
            # image is present and --cache-from short-circuits to local.
            local_img = subprocess.run(
                ['docker', 'image', 'inspect', self.image],
                capture_output=True).returncode == 0
            if local_img:
                cmd.extend(['--cache-from', self.image])
            else:
                print("[CXF] Skipping --cache-from (no prior local image)")

            cmd.extend(['-t', self.image, source_dir])

            r = subprocess.run(cmd, capture_output=False, env=env)
            return r.returncode == 0

        # Fallback: pre-built WAR path (unchanged behaviour from prior patch)
        if not os.path.isfile(self.offline_war):
            print("[CXF] Neither source/ nor offline oauth.war present under "
                  f"{self.offline_dir}")
            return False
        return self._ensure_image_from_prebuilt_war()

    def _prepull_base_images(self, images: List[str]) -> Optional[str]:
        """Pull the named base images, retrying across registry candidates
        until one registry succeeds for all of them.

        Returns the registry hostname that worked (suitable to feed into
        `--build-arg BASE_REGISTRY=...`), or None if every candidate
        registry fails for at least one image.

        The candidate list is intentionally small and ordered by observed
        reliability: docker.1ms.run is the healthy mirror in the user's
        current daemon.json; the Aliyun ACR mirror is independent of
        Docker Hub and survives Docker Hub-wide outages.
        """
        cxf_cfg = self.config.get('cxf_oauth', {})
        candidates = cxf_cfg.get('base_image_registries', [
            'docker.1ms.run',
            'registry.cn-hangzhou.aliyuncs.com',
            'docker.io',
        ])
        max_retries = int(cxf_cfg.get('pull_retries', 3))
        backoff_s = float(cxf_cfg.get('pull_backoff_s', 5.0))

        for registry in candidates:
            print(f"[CXF] Pre-pulling base images from {registry} ...")
            all_ok = True
            for img in images:
                # Aliyun ACR + Docker Hub layout the namespace as
                # <registry>/library/<image>, while a few mirrors elide the
                # /library/ prefix.  docker.1ms.run accepts both; we use the
                # canonical form to stay portable.
                ref = f"{registry}/library/{img}"
                ok = False
                for attempt in range(1, max_retries + 1):
                    r = subprocess.run(
                        ['docker', 'pull', ref],
                        capture_output=True, text=True, timeout=600)
                    if r.returncode == 0:
                        ok = True
                        break
                    err_tail = (r.stderr or '').strip().splitlines()[-1:] or ['(no stderr)']
                    print(f"[CXF]   attempt {attempt}/{max_retries} pull {ref} failed: {err_tail[0]}")
                    if '429' in (r.stderr or '') or 'Too Many Requests' in (r.stderr or ''):
                        # Hard-throttled by THIS registry — skip ahead to
                        # the next candidate immediately, no backoff.
                        ok = False
                        break
                    time.sleep(backoff_s * attempt)
                if not ok:
                    all_ok = False
                    break

                # Re-tag to the unprefixed form expected by the Dockerfile's
                # FROM <reg>/library/<img> resolver — avoids a second pull
                # if the registry-arg matches what we just downloaded.
                subprocess.run(
                    ['docker', 'tag', ref, f"{registry}/library/{img}"],
                    capture_output=True)

            if all_ok:
                return registry
            print(f"[CXF] Registry {registry} could not satisfy all base images; trying next ...")
        return None

    def _ensure_image_from_prebuilt_war(self) -> bool:
        staging = os.path.join(self.work_dir, 'docker_stage')
        os.makedirs(staging, exist_ok=True)

        # Resolve WAR — offline first, then built output
        war_src = None
        if self.prefer_offline and os.path.isfile(self.offline_war):
            war_src = self.offline_war
        else:
            for root, _, files in os.walk(CXF_SOURCE_DIR):
                for f in files:
                    if f.endswith('.war') and 'oauth' in f.lower():
                        war_src = os.path.join(root, f)
                        break
                if war_src:
                    break
        if not war_src:
            print("[CXF] No oauth .war located (offline + source both empty)")
            return False
        shutil.copy2(war_src, os.path.join(staging, 'oauth.war'))

        # JaCoCo agent jar — offline-staged copy takes precedence
        if os.path.isfile(self.offline_agent_jar):
            shutil.copy2(self.offline_agent_jar,
                         os.path.join(staging, 'jacocoagent.jar'))
        else:
            self._stage_jacoco_agent(staging)

        # File-based entrypoint with `set -f` to disable pathname expansion so
        # JaCoCo includes patterns containing `*` aren't glob-mangled by the
        # shell.  Also injects JACOCO_OPTS into CATALINA_OPTS at runtime,
        # which the original ENV approach could not do (build-time $JAVA_OPTS
        # was always empty).
        entrypoint_sh = (
            "#!/bin/sh\n"
            "set -f\n"
            "# shellcheck disable=SC2086\n"
            "export CATALINA_OPTS=\"$JACOCO_OPTS $CATALINA_OPTS\"\n"
            "exec /usr/local/tomcat/bin/catalina.sh run\n"
        )
        with open(os.path.join(staging, 'entrypoint.sh'), 'w') as f:
            f.write(entrypoint_sh)

        dockerfile = """\
FROM tomcat:9-jre11
COPY oauth.war /usr/local/tomcat/webapps/services.war
COPY jacocoagent.jar /opt/jacoco/jacocoagent.jar
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8080 6300
ENTRYPOINT ["/entrypoint.sh"]
"""
        with open(os.path.join(staging, 'Dockerfile'), 'w') as f:
            f.write(dockerfile)

        r = subprocess.run(['docker', 'build', '-t', self.image, staging],
                           capture_output=False)
        return r.returncode == 0

    def _start_container(self) -> bool:
        jacoco_cfg = self.config.get('jacoco', {})
        agent_port = jacoco_cfg.get('agent_port', 6300)
        includes = jacoco_cfg.get('includes', [
            'org.apache.cxf.rs.security.oauth2.*',
            'org.apache.cxf.rs.security.oidc.*',
            'org.apache.cxf.rs.security.jose.*',
        ])
        agent_opts = (f"output=tcpserver,address=0.0.0.0,port={agent_port},"
                      f"includes={':'.join(includes)}")
        jacoco_opts = f"-javaagent:/opt/jacoco/jacocoagent.jar={agent_opts} -Xmx1024m"

        cmd = [
            'docker', 'run', '-d',
            '--name', self.container_name,
            '-p', f'{self.http_port}:8080',
            '-p', f'{agent_port}:{agent_port}',
            # JACOCO_OPTS is consumed by the entrypoint and prepended to
            # CATALINA_OPTS at runtime — works across Tomcat 9/10.
            '-e', f'JACOCO_OPTS={jacoco_opts}',
            self.image,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"[CXF] docker run failed: {r.stderr}")
            return False
        return True

    def _prepare_classpaths(self) -> None:
        lib_dir = os.path.join(os.path.abspath(self.jacoco.work_dir), 'cxf_lib')
        os.makedirs(lib_dir, exist_ok=True)
        war_out = os.path.join(lib_dir, 'services.war')
        subprocess.run(['docker', 'cp',
                        f'{self.container_name}:/usr/local/tomcat/webapps/services.war',
                        war_out], capture_output=True)
        if not os.path.exists(war_out):
            # the image's entrypoint deploys the app as ROOT.war
            subprocess.run(['docker', 'cp',
                            f'{self.container_name}:/usr/local/tomcat/webapps/ROOT.war',
                            war_out], capture_output=True)
        if not os.path.exists(war_out):
            print("[CXF] Could not copy services.war/ROOT.war out of container; "
                  "coverage reports will be empty")
            return
        classpaths: List[str] = []
        extract_dir = os.path.join(lib_dir, 'extracted')
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        with zipfile.ZipFile(war_out, 'r') as zf:
            zf.extractall(extract_dir)
        classes = os.path.join(extract_dir, 'WEB-INF', 'classes')
        if os.path.isdir(classes):
            classpaths.append(classes)
        # Narrow to the JARs that actually contain the instrumented packages.
        # Over-specifying produces duplicate <class> entries in the XML report.
        wanted_prefixes = (
            'cxf-rt-rs-security-oauth2',   # core OAuth2 services/grants/filters
            'cxf-rt-rs-security-jose',     # only if JWT bearer grant is live
        )
        lib = os.path.join(extract_dir, 'WEB-INF', 'lib')
        if os.path.isdir(lib):
            for fname in os.listdir(lib):
                if fname.endswith('.jar') and any(fname.startswith(p) for p in wanted_prefixes):
                    classpaths.append(os.path.join(lib, fname))
        # De-duplicate while preserving order
        seen = set()
        classpaths = [p for p in classpaths if not (p in seen or seen.add(p))]
        if not classpaths:
            print("[CXF] No classpath entries found — JaCoCo report will be empty")
            return
        self.jacoco.set_classpaths(classpaths)
        print(f"[CXF] JaCoCo classpaths ready: {len(classpaths)} (trimmed for report size)")

    def _cleanup_container(self):
        subprocess.run(['docker', 'rm', '-f', self.container_name], capture_output=True)

    def _print_logs(self, tail: int = 80):
        r = subprocess.run(['docker', 'logs', '--tail', str(tail), self.container_name],
                           capture_output=True, text=True)
        print(r.stdout); print(r.stderr)


def create_test_config_cxf() -> str:
    config = {
        "name": "oauth-cxf-fuzzer",
        "target_type": "cxf_oauth",
        "protocol": "OAUTH",
        "implementation": "Apache CXF rs-security-oauth2",
        "output_dir": "out/oauth_cxf_coverage",
        "oauth": {
            "base_url": "http://127.0.0.1:8081",
            "realm": "",
            "client_id": "fuzz-client",
            "client_secret": "fuzz-client-secret",
            "redirect_uri": "http://127.0.0.1:7777/callback",
            "user": "alice", "password": "alice",
            "scope": "openid read_resource"
        },
        "cxf_oauth": {
            "container_name": "cxf-oauth-fuzz",
            "image": "cxf-oauth:latest",
            "http_port": 8081,
            "jacoco_enabled": True,
            "startup_timeout": 180,
            "prefer_offline": True,
            "offline_dir": "targets_manager/cxf_offline",
            "sample_path": "distribution/src/main/release/samples/jax_rs/oauth2"
        },
        "jacoco": {
            "version": "0.8.14",
            "work_dir": "jacoco_tools",
            "agent_port": 6300,
            "dump_every_n": 25,
            "includes": [
                "org.apache.cxf.rs.security.oauth2.*",
                "org.apache.cxf.rs.security.oidc.*",
                "org.apache.cxf.rs.security.jose.*",
                "org.apache.cxf.rs.security.jwt.*",
                "org.apache.cxf.jaxrs.provider.*"
            ]
        },
        "fuzzing": {
            "max_iterations": 3000,
            "differential_coverage": True,
            "baseline_refresh_every": 25,
            "canonicalize_sequences": True,
            "save_interesting_cases": False
        }
    }
    os.makedirs("configs", exist_ok=True)
    path = "configs/oauth_cxf.json"
    with open(path, 'w') as f: json.dump(config, f, indent=2)
    return path


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(
        description='Apache CXF rs-security-oauth2 Target Manager')
    p.add_argument('--config', default='configs/oauth_cxf.json')
    p.add_argument('--action',
                   choices=['start', 'stop', 'status', 'init-config'],
                   default='start')
    args = p.parse_args()

    if args.action == 'init-config':
        created = create_test_config_cxf()
        print(f"Config written: {created}")
        raise SystemExit(0)

    if not os.path.exists(args.config):
        print(f"[CXF] {args.config} not found — bootstrapping default")
        create_test_config_cxf()

    with open(args.config) as f:
        cfg = json.load(f)

    m = CxfOAuthManager(cfg)
    if args.action == 'start':
        raise SystemExit(0 if m.start() else 1)
    if args.action == 'stop':
        m.stop(); raise SystemExit(0)
    if args.action == 'status':
        print("healthy" if m.is_healthy() else "unhealthy")
        raise SystemExit(0)
