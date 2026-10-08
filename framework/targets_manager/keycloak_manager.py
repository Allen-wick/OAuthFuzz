#!/usr/bin/env python3
"""
Keycloak Startup Script with JaCoCo Integration
Starts Keycloak with coverage collection enabled
"""

import subprocess
import time
import requests
import json
import os
import sys
from typing import Dict
from core.coverage import JaCoCoManager
from core.paths import PROJECT_ROOT
from targets_manager.base import TargetManager


class KeycloakManager(TargetManager):
    """Keycloak server manager with JaCoCo integration"""
    
    def __init__(self, config: Dict):
        super().__init__(config)  # base init: _atexit_registered etc.
        self.config = config
        self.jacoco = JaCoCoManager(work_dir=self.config.get('jacoco', {}).get('work_dir', os.path.join(PROJECT_ROOT, 'jacoco_tools')),
                                    version=self.config.get('jacoco', {}).get('version'))
        self.process = None
        self.base_url = config.get('oauth', {}).get('base_url', 'http://127.0.0.1:8080')
        self.health_check_url = config.get('keycloak', {}).get('health_check_url', f'{self.base_url}/realms/master')
        self.container_name = self.config.get('keycloak', {}).get('container_name', 'keycloak-fuzz-coverage')

    def start(self) -> bool:
        return self.start_keycloak()

    def stop(self) -> None:
        self.stop_keycloak()

    def is_healthy(self) -> bool:
        try:
            resp = requests.get(self.health_check_url, timeout=5)
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def import_config(self, config_file: str = None) -> bool:
        if config_file:
            return self.import_realm(config_file)
        # Create realm/client/user programmatically from manager config
        oauth = self.config.get('oauth', {})
        realm_name = oauth.get('realm', 'fuzz')
        client_id = oauth.get('client_id', 'fuzz-client')
        client_secret = oauth.get('client_secret', 'fuzz-client-secret')
        username = oauth.get('user', 'testuser')
        password = oauth.get('password', 'testpass')
        redirect_uri = oauth.get('redirect_uri', 'http://127.0.0.1:7777/callback')

        print(f"[*] Creating realm '{realm_name}' programmatically...")
        for attempt in range(3):
            token = self._get_admin_token(attempt + 1)
            if not token:
                if attempt < 2:
                    time.sleep(5)
                continue
            if not self._create_realm_simple(realm_name, token):
                if attempt < 2:
                    time.sleep(5)
                continue
            if not self._create_client(realm_name, {
                'clientId': client_id,
                'name': 'OAuth Fuzzing Client',
                'protocol': 'openid-connect',
                'publicClient': False,
                'enabled': True,
                'redirectUris': [redirect_uri],
                'webOrigins': ['+'],
                'clientAuthenticatorType': 'client-secret',
                'secret': client_secret,
                'directAccessGrantsEnabled': True,
                'standardFlowEnabled': True,
                'bearerOnly': False,
            }, token):
                if attempt < 2:
                    time.sleep(5)
                continue
            if not self._create_user(realm_name, {
                'username': username,
                'email': f'{username}@example.com',
                'firstName': 'Test',
                'lastName': 'User',
                'enabled': True,
                'emailVerified': True,
                'credentials': [{'type': 'password', 'value': password, 'temporary': False}],
            }, token):
                if attempt < 2:
                    time.sleep(5)
                continue
            print(f"[+] Realm '{realm_name}' ready with client '{client_id}' and user '{username}'")
            return True
        print(f"[!] Failed to create realm after 3 attempts")
        return False


    def _restore_classpaths_on_reuse(self):
        """The reuse path skips the deploy-time jar selection, so report
        generation would run with empty classpaths. Layout-agnostic restore:
        recursively glob the instrumented jars under keycloak_lib, keep the
        RUNNING container's version (duplicate versions make JaCoCo abort on
        same-name classes), plus the quarkus runtime jars."""
        import glob as _glob
        lib_root = os.path.join(os.path.abspath(self.jacoco.work_dir), 'keycloak_lib')
        version = self.config.get('keycloak', {}).get('version', '26.7.4')
        exclude = ('sssd-federation', 'kerberos-federation', 'themes',
                   'admin-ui', 'account-ui')
        jars = []
        for p in _glob.glob(os.path.join(lib_root, '**', 'org.keycloak.keycloak-*.jar'),
                            recursive=True):
            base = os.path.basename(p)
            if any(ex in base for ex in exclude):
                continue
            if version in base or not any(v in base for v in ('26.0.0', '26.4.6', '26.7.0', '26.7.4')):
                jars.append(p)
        # NOTE: no io.quarkus jars — the agent instruments org.keycloak.* only,
        # and sweeping the quarkus runtime (lib/lib/boot + lib/quarkus overlap)
        # makes JaCoCo abort on same-name classes from different artifacts.
        # dedupe by basename: the copied lib tree nests 'lib/lib' (historical
        # wrapper), so the same quarkus/keycloak jar appears at two depths and
        # JaCoCo aborts on duplicate classes
        seen_names = {}
        for p in jars:
            seen_names.setdefault(os.path.basename(p), p)
        jars = sorted(seen_names.values())
        if jars:
            self.jacoco.set_classpaths([os.path.abspath(p) for p in jars])
            print(f"[KC] classpaths restored on reuse ({len(jars)} jars, version {version})")

    def start_keycloak(self):
        """Start Keycloak with offline-instrumented classes (no javaagent)"""
        print("Starting Keycloak with offline instrumentation (JaCoCo coverage collection)...")

        # Try to reuse a stopped container first
        reuse = self._try_reuse_stopped(health_timeout=60)
        if reuse is True:
            print(f"Keycloak reused existing container: {self.container_name}")
            self._restore_classpaths_on_reuse()
            return True
        if reuse is False:
            # Container exists but unhealthy — remove and redeploy
            print(f"  Existing container unhealthy, redeploying...")
            subprocess.run(['docker', 'rm', '-f', self.container_name],
                           capture_output=True, text=True, timeout=30)

        # 1) 从镜像预复制 /opt/keycloak/lib 到宿主机（临时容器）
        host_jacoco_dir = os.path.abspath(self.jacoco.work_dir)
        local_lib_root = os.path.join(host_jacoco_dir, "keycloak_lib")
        os.makedirs(local_lib_root, exist_ok=True)

        # 自动清理：每次测试前严格清理旧产物
        try:
            import shutil as _sh
            for p in [
                os.path.join(host_jacoco_dir, "instrument_work"),
                os.path.join(host_jacoco_dir, "instrumented_main"),
            ]:
                if os.path.exists(p):
                    _sh.rmtree(p, ignore_errors=True)
            exec_file = os.path.join(host_jacoco_dir, "coverage.exec")
            if os.path.exists(exec_file):
                os.remove(exec_file)
            reports_dir = os.path.join(host_jacoco_dir, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            report_xml = os.path.join(reports_dir, "coverage.xml")
            if os.path.exists(report_xml):
                os.remove(report_xml)
            print("[Clean] Removed old instrumentation and coverage artifacts")
        except Exception as _e:
            print(f"[Clean] Warning: cleanup failed: {_e}")

        print("[KeycloakManager] Pre-copying /opt/keycloak/lib from image...")
        kc_version = self.config.get('keycloak', {}).get('version', '26.7.4')
        kc_image = f"quay.io/keycloak/keycloak:{kc_version}"
        tmp_id = None
        try:
            r = subprocess.run(
                ['docker', 'create', kc_image],
                check=True, capture_output=True, text=True
            )
            tmp_id = r.stdout.strip()
            subprocess.run(
                ['docker', 'cp', f'{tmp_id}:/opt/keycloak/lib', local_lib_root],
                check=True, capture_output=True, text=True
            )
        finally:
            if tmp_id:
                subprocess.run(['docker', 'rm', '-f', tmp_id], capture_output=True, text=True)

        # 4) 启动容器（启用 -javaagent=tcpserver），实时采集覆盖率到 dump（coverage.exec）
        jvm_args = self.config.get('keycloak', {}).get('jvm_args', [])
        # 构造 -javaagent 参数（includes 从配置读取，默认为 org.keycloak.*）
        inc = self.config.get('jacoco', {}).get('includes', ['org.keycloak.*'])
        preferred_port = int(self.config.get('jacoco', {}).get('agent_port', 6300))
        # 端口自检与回退：避免 6300 被占用导致容器启动失败
        def _pick_free_port(pref: int, tries: int = 10) -> int:
            import socket
            for p in [pref] + list(range(pref + 1, pref + 1 + tries)):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    s.bind(("0.0.0.0", p))
                    s.close()
                    return p
                except OSError:
                    s.close()
                    continue
            return pref
        agent_port = _pick_free_port(preferred_port)
        if agent_port != preferred_port:
            try:
                self.config.setdefault('jacoco', {})['agent_port'] = agent_port
                print(f"[KeycloakManager] Agent port {preferred_port} busy, switched to {agent_port}")
            except Exception:
                pass
        agent_opts = f"output=tcpserver,address=0.0.0.0,port={agent_port},includes={':'.join(inc)}"
        agent_arg = f"-javaagent:/opt/jacoco/{self.jacoco.agent_jar}={agent_opts}"
        # 兼容性：将 JaCoCo runtime 加入引导类路径，避免类加载问题
        offline_props = [
            "-Xbootclasspath/a:/opt/jacoco/jacocoagent.jar"
        ]
        all_jvm_args = jvm_args + offline_props + [agent_arg]

        # 选择 Keycloak 主目录（用于准备报告 classpaths）
        lib_root = os.path.join(local_lib_root, 'lib')
        candidate_main_dirs = [
            os.path.join(lib_root, 'lib', 'main'),
            os.path.join(lib_root, 'main'),
        ]
        main_dir = None
        for d in candidate_main_dirs:
            if os.path.isdir(d):
                main_dir = d
                break
        if not main_dir:
            print(f"[KeycloakManager] ERROR: main dir not found under {lib_root}")
            return False

        # 自动消毒：每次测试前剔除冲突项（主类与内部类），并移除 Multi-Release 路径与跨JAR重复
        # 重要：为报告保留一份未修改的 JAR 副本
        try:
            import shutil
            original_jars_backup = os.path.join(host_jacoco_dir, "original_jars_backup")
            if not os.path.exists(original_jars_backup):
                os.makedirs(original_jars_backup, exist_ok=True)
                for f in os.listdir(main_dir):
                    if f.endswith('.jar') and 'org.keycloak' in f:
                        src = os.path.join(main_dir, f)
                        dst = os.path.join(original_jars_backup, f)
                        shutil.copy2(src, dst)
                print(f"[Sanitize] Backed up original JARs to {original_jars_backup}")
            removed_total = self._sanitize_conflict_classes(main_dir)
            if removed_total > 0:
                print(f"[Sanitize] Total removed entries: {removed_total}")
        except Exception as e:
            print(f"[Sanitize] Failed to sanitize JARs: {e}")

        cmd = [
            'docker', 'run', '--rm', '-d',
            '--name', self.container_name,
            '-p', f"{int(self.config.get('keycloak', {}).get('host_http_port', 8080))}:8080",
            '-p', f'{agent_port}:{agent_port}',
            '-v', f"{host_jacoco_dir}:/opt/jacoco",
            '-e', 'KC_BOOTSTRAP_ADMIN_USERNAME=admin',
            '-e', 'KC_BOOTSTRAP_ADMIN_PASSWORD=admin',
            '-e', f'JAVA_OPTS_APPEND={" ".join(all_jvm_args)}',
            kc_image,
            'start-dev'
        ]

        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            container_id = result.stdout.strip()
            print(f"Keycloak container started: {container_id}")

            # 等待服务就绪
            if not self._wait_for_keycloak():
                print("Keycloak failed to start properly")
                # 启动失败时输出容器日志，便于定位
                try:
                    logs = subprocess.run(['docker', 'logs', '--tail', '200', self.container_name],
                                          check=True, capture_output=True, text=True)
                    print("=== Keycloak recent logs  as le(200 lines) ===")
                    print(logs.stdout)
                except subprocess.CalledProcessError:
                    pass
                return False

            print("Keycloak is ready with online coverage (JaCoCo tcpserver) enabled!")

            # 设置报告使用的 classpaths（仅限 Keycloak 核心 JAR）
            # 重要：只选择与容器版本匹配的 JAR
            target_version = self.config.get('keycloak', {}).get('version', '26.7.4')
            selected = []
            for f in os.listdir(main_dir):
                if f.endswith('.jar') and f.startswith('org.keycloak.keycloak-'):
                    # 只选择正确版本的 JAR
                    if target_version in f:
                        selected.append(os.path.join(main_dir, f))
            if not selected:
                # 回退：选择所有 org.keycloak JAR
                for f in os.listdir(main_dir):
                    if f.endswith('.jar') and f.startswith('org.keycloak.') and target_version in f:
                        selected.append(os.path.join(main_dir, f))
            classpaths = [os.path.abspath(p) for p in selected]
            self.jacoco.set_classpaths(classpaths)
            try:
                self.config.setdefault('jacoco', {})['classpaths'] = classpaths
            except Exception:
                pass
            try:
                missing = [p for p in classpaths if not os.path.exists(p)]
                print(f"[KeycloakManager] Classpaths(JAR) prepared ({len(classpaths)}), missing={len(missing)}")
                if missing:
                    print(f"[KeycloakManager] Missing sample: {missing[:5]}")
            except Exception:
                pass
            return True

        except subprocess.CalledProcessError as e:
            print(f"Failed to start Keycloak: {e}")
            print(f"STDERR: {e.stderr}")
            return False
    
    def _wait_for_jacoco_port(self, port: int, timeout: int = 60) -> bool:
        """Wait until JaCoCo agent tcpserver port is listening on host"""
        import socket
        start = time.time()
        while time.time() - start < timeout:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=2):
                    return True
            except OSError:
                time.sleep(1)
        return False

    def _wait_for_keycloak(self, timeout: int = 120) -> bool:
        """增强版等待逻辑：同时检查管理API可用性"""
        print("Waiting for Keycloak to be ready (including admin API)...")
        
        # 新增管理API检查端点
        admin_check_url = f"{self.base_url}/admin/serverinfo"
        start_time = time.time()
        interval = 2
        
        while time.time() - start_time < timeout:
            try:
                # 1. 检查基础Realm是否就绪
                realm_response = requests.get(self.health_check_url, timeout=10)
                # 2. 检查管理API是否就绪（不需要认证，但需返回401而非503）
                admin_response = requests.get(admin_check_url, timeout=10)
                
                # 两个条件同时满足：基础Realm 200，管理API 401（未认证）
                if realm_response.status_code == 200 and admin_response.status_code == 401:
                    print("\nKeycloak and admin API are fully ready")
                    return True
            except requests.exceptions.RequestException:
                pass
            
            time.sleep(interval)
            interval = min(interval * 1.2, 10)  # 动态延长间隔
        
        return False
    
    def stop_keycloak(self):
        """Stop (but do not remove) Keycloak container for reuse."""
        print("Stopping Keycloak...")
        self._stop_container()
    
    def import_realm(self, realm_file: str, max_retries: int = 3) -> bool:
        """Import realm with retries and detailed logging"""
        if not os.path.exists(realm_file):
            print(f"Realm file not found: {realm_file}")
            return False
        
        print(f"Importing realm configuration (max retries: {max_retries})...")
        
        for attempt in range(max_retries):
            try:
                # 获取管理员令牌（新增详细日志）               
                token = self._get_admin_token(attempt+1)
                if not token:
                    if attempt < max_retries - 1:
                        time.sleep(5)
                    continue
                
                with open(realm_file, 'r') as f:
                    realm_data = json.load(f)
                
                realm_name = realm_data.get("realm")
                if not realm_name:
                    print("Invalid realm config: missing 'realm' field")
                    return False

                # 1) 先创建最小 Realm（避免直接完整导入触发 stream 错误）
                if not self._create_realm_simple(realm_name, token):
                    if attempt < max_retries - 1:
                        time.sleep(5)
                    continue

                # 2) 创建 client（若存在）
                clients = realm_data.get("clients", [])
                if clients:
                    if not self._create_client(realm_name, clients[0], token):
                        if attempt < max_retries - 1:
                            time.sleep(5)
                        continue

                # 3) 创建用户（若存在）
                users = realm_data.get("users", [])
                if users:
                    if not self._create_user(realm_name, users[0], token):
                        if attempt < max_retries - 1:
                            time.sleep(5)
                        continue

                print("Realm, client, and user setup completed successfully!")
                return True
            
            except json.JSONDecodeError as e:
                print(f"Realm file JSON decode error (attempt {attempt+1}): {e}")
                break  # JSON错误无需重试
            except Exception as e:
                print(f"Import error (attempt {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(5)
        
        print("All retries exhausted. Failed to import realm.")
        return False
    
    def get_coverage_data(self):
        """Get current coverage data"""
        try:
            port = self.config.get('jacoco', {}).get('agent_port', 6300)
            self.jacoco.dump_coverage(port=port)
            xml = self.jacoco.generate_report()
            if xml:
                return self.jacoco.parse_coverage_xml(xml)
        except Exception as e:
            print(f"Get coverage error: {e}")
        return None
    
    def _get_admin_token(self, attempt_idx: int = 1) -> str:
        """Get admin access token"""
        token_url = f"{self.base_url}/realms/master/protocol/openid-connect/token"
        print(f"Attempt {attempt_idx}: Getting admin token from {token_url}")
        resp = requests.post(
            token_url,
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "admin",
                "password": "admin"
            },
            timeout=10
        )
        if resp.status_code != 200:
            print(f"Token request failed: {resp.status_code} - {resp.text}")
            return ""
        token = resp.json().get("access_token", "")
        if not token:
            print("No access token received")
        return token

    def _create_realm_simple(self, realm_name: str, access_token: str) -> bool:
        """Create a minimal realm first"""
        url = f"{self.base_url}/admin/realms"
        payload = {"realm": realm_name, "enabled": True}
        print(f"Creating minimal realm '{realm_name}' via {url}")
        resp = requests.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            timeout=20
        )
        if resp.status_code in (201, 204):
            print(f"Realm '{realm_name}' created")
            return True
        if resp.status_code == 409:
            print(f"Realm '{realm_name}' already exists, continuing")
            return True
        print(f"Create realm failed: {resp.status_code} - {resp.text}")
        return False

    def _create_client(self, realm_name: str, client: Dict, access_token: str) -> bool:
        """Create client in realm"""
        url = f"{self.base_url}/admin/realms/{realm_name}/clients"
        # 过滤或重命名需要的字段，避免不兼容属性
        payload = {
            "clientId": client.get("clientId", "fuzz-client"),
            "name": client.get("name", "OAuth Fuzzing Client"),
            "protocol": client.get("protocol", "openid-connect"),
            "publicClient": client.get("publicClient", False),
            "enabled": client.get("enabled", True),
            "redirectUris": client.get("redirectUris", []),
            "webOrigins": client.get("webOrigins", []),
            "clientAuthenticatorType": client.get("clientAuthenticatorType", "client-secret"),
            "secret": client.get("secret", "fuzz-client-secret"),
            "directAccessGrantsEnabled": client.get("directAccessGrantsEnabled", True),
            "standardFlowEnabled": client.get("standardFlowEnabled", True),
            "bearerOnly": client.get("bearerOnly", False),
            "frontchannelLogout": client.get("frontchannelLogout", False)
        }
        print(f"Creating client '{payload['clientId']}' in realm '{realm_name}' via {url}")
        resp = requests.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            timeout=20
        )
        if resp.status_code in (201, 204):
            print(f"Client '{payload['clientId']}' created")
            return True
        if resp.status_code == 409:
            print(f"Client '{payload['clientId']}' already exists, continuing")
            return True
        print(f"Create client failed: {resp.status_code} - {resp.text}")
        return False

    def _create_user(self, realm_name: str, user: Dict, access_token: str) -> bool:
        """Create test user in realm"""
        url = f"{self.base_url}/admin/realms/{realm_name}/users"
        payload = {
            "username": user.get("username", "testuser"),
            "email": user.get("email", "testuser@example.com"),
            "firstName": user.get("firstName", "Test"),
            "lastName": user.get("lastName", "User"),
            "enabled": user.get("enabled", True),
            "emailVerified": user.get("emailVerified", True),
            "credentials": [{
                "type": "password",
                "value": (user.get("credentials", [{}])[0].get("value") or "testpass"),
                "temporary": False
            }]
        }
        print(f"Creating user '{payload['username']}' in realm '{realm_name}' via {url}")
        resp = requests.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            },
            timeout=20
        )
        if resp.status_code in (201, 204):
            print(f"User '{payload['username']}' created")
            return True
        if resp.status_code == 409:
            print(f"User '{payload['username']}' already exists, continuing")
            return True
        print(f"Create user failed: {resp.status_code} - {resp.text}")
        return False

    def _prepare_classfiles(self):
        """Copy Keycloak classfiles (jars) from container for JaCoCo report"""
        local_dir = os.path.join(self.jacoco.work_dir, "keycloak_lib")
        os.makedirs(local_dir, exist_ok=True)
        try:
            subprocess.run(
                ['docker', 'cp', f'{self.container_name}:/opt/keycloak/lib', local_dir],
                check=True, capture_output=True, text=True
            )
            # Edited: 复制 providers 与 quarkus 依赖目录，避免遗漏扩展模块
            try:
                subprocess.run(
                    ['docker', 'cp', f'{self.container_name}:/opt/keycloak/providers', local_dir],
                    check=True, capture_output=True, text=True
                )
            except subprocess.CalledProcessError:
                pass
            try:
                subprocess.run(
                    ['docker', 'cp', f'{self.container_name}:/opt/keycloak/lib/quarkus', local_dir],
                    check=True, capture_output=True, text=True
                )
            except subprocess.CalledProcessError:
                pass

            lib_root = os.path.join(local_dir, 'lib')
            providers_root = os.path.join(local_dir, 'providers')
            quarkus_root = os.path.join(local_dir, 'lib', 'quarkus')

            # 修正：Keycloak 26 的布局通常为 lib/lib/main
            candidate_main_dirs = [
                os.path.join(lib_root, 'lib', 'main'),  # 首选
                os.path.join(lib_root, 'main'),         # 兼容旧布局
            ]

            main_dir = None
            for d in candidate_main_dirs:
                if os.path.exists(d):
                    main_dir = d
                    break
            if not main_dir:
                # 回退：仍然无法找到 main 目录时尝试根目录（不期望使用）
                main_dir = lib_root

            # 仅选择核心 Keycloak JAR，避免目录导致重复类冲突
            core_prefixes = [
                "org.keycloak.keycloak-core-",
                "org.keycloak.keycloak-services-",
                "org.keycloak.keycloak-server-spi-",
                "org.keycloak.keycloak-server-spi-private-",
                "org.keycloak.keycloak-quarkus-server-",
                "org.keycloak.keycloak-model-jpa-",
                "org.keycloak.keycloak-model-infinispan-",
                "org.keycloak.keycloak-common-",
                "org.keycloak.keycloak-crypto-"
            ]
            # # Edited: 加入常用依赖前缀（Jackson/Quarkus）
            # dep_prefixes = [
            #     "com.fasterxml.jackson.",
            #     "io.quarkus."
            # ]
            exclude_keywords = [
                "sssd-federation",
                "kerberos-federation",
                "themes",
                "admin-ui",
                "account-ui"
            ]

            selected_jars = []
            try:
                # main 目录核心 jar（严格按 core_prefixes 选择）
                for fname in os.listdir(main_dir):
                    if not fname.endswith(".jar"):
                        continue
                    if any(fname.startswith(pfx) for pfx in core_prefixes) and not any(ex in fname for ex in exclude_keywords):
                        selected_jars.append(os.path.join(main_dir, fname))

                # 宽泛回补：如核心未覆盖所有 org.keycloak.keycloak-* 模块，补全但仍排除冲突关键词
                wide_jars = []
                for fname in os.listdir(main_dir):
                    if not fname.endswith(".jar"):
                        continue
                    if fname.startswith("org.keycloak.keycloak-") and not any(ex in fname for ex in exclude_keywords):
                        p = os.path.join(main_dir, fname)
                        if p not in selected_jars:
                            wide_jars.append(p)

                # quarkus 依赖：匹配 io.quarkus.*，用于覆盖agent includes中的 Quarkus 包
                quarkus_jars = []
                if os.path.exists(quarkus_root):
                    for fname in os.listdir(quarkus_root):
                        if fname.endswith(".jar") and fname.startswith("io.quarkus."):
                            quarkus_jars.append(os.path.join(quarkus_root, fname))
            except Exception as e:
                print(f"Jar selection error: {e}")

            # 构造两套 classpaths：聚合 与 模块
            qrun = os.path.join(lib_root, 'quarkus-run.jar')
            aggregate_classpaths = [os.path.abspath(qrun)] if os.path.exists(qrun) else []
            module_classpaths = [os.path.abspath(p) for p in (selected_jars + wide_jars + quarkus_jars)]

            # 默认：优先使用聚合模式，避免重复类冲突；若缺失则用模块模式
            classpaths = aggregate_classpaths if aggregate_classpaths else module_classpaths

            self.jacoco.set_classpaths(classpaths)
            try:
                self.config.setdefault('jacoco', {})['classpaths'] = classpaths
                self.config['jacoco']['classpaths_aggregate'] = aggregate_classpaths
                self.config['jacoco']['classpaths_modules'] = module_classpaths
            except Exception:
                pass
            try:
                missing = [p for p in classpaths if not os.path.exists(p)]
                print(f"[KeycloakManager] Classpaths(JAR) prepared ({len(classpaths)}), missing={len(missing)}")
                if missing:
                    print(f"[KeycloakManager] Missing sample: {missing[:5]}")
                print(f"[KeycloakManager] Aggregate({len(aggregate_classpaths)}), Modules({len(module_classpaths)})")
            except Exception:
                pass

        except subprocess.CalledProcessError as e:
            pass

    def get_recent_logs(self, tail: int = 500, keywords: list = None) -> str:
        """Fetch recent Keycloak container logs for vulnerability hints. Optional keyword filtering."""
        try:
            result = subprocess.run(
                ['docker', 'logs', '--tail', str(tail), self.container_name],
                check=True, capture_output=True, text=True
            )
            logs = result.stdout
            if keywords:
                lines = logs.splitlines()
                lowered = [kw.lower() for kw in keywords]
                hits = [ln for ln in lines if any(kw in ln.lower() for kw in lowered)]
                summary = "\n=== Filtered keyword hits ===\n" + ("\n".join(hits) if hits else "(no keyword hits)")
                return logs + "\n" + summary
            return logs
        except subprocess.CalledProcessError as e:
            return f"Failed to fetch logs: {e.stderr or str(e)}"

    def _sanitize_conflict_classes(self, main_dir: str) -> int:
        """
        从用于报告的本地 JAR 副本中删除冲突类：
        - 统一剔除 Multi-Release 路径（META-INF/versions/*）下的目标类（含内部类）
        - 跨JAR去重：仅保留首次出现的主版本类（含内部类），其他JAR删除同名类
        目标前缀包含：
          - org/keycloak/jose/jwk/JWKParser
          - org/keycloak/jose/jwk/JWKBuilder
          - org/keycloak/utils/ServicesUtils（含内部类如 ServicesUtils$1）
        返回删除的总条目数
        """
        import zipfile, os as _os
        # 以“类前缀”匹配，可覆盖主类与其内部类（$...）
        target_prefixes = [
            'org/keycloak/jose/jwk/JWKParser',
            'org/keycloak/jose/jwk/JWKBuilder',
            'org/keycloak/utils/ServicesUtils',
            'org/keycloak/federation/sssd/impl/AvailabilityChecker'
        ]
        # 收集 keycloak-* JAR（报告用）
        keycloak_jars = [os.path.join(main_dir, f) for f in os.listdir(main_dir)
                         if f.startswith('org.keycloak.keycloak-') and f.endswith('.jar')]
        # 首次扫描：记录每个前缀的主版本类拥有者（首次出现的JAR）
        seen_owner = {}
        for jar_path in keycloak_jars:
            try:
                with zipfile.ZipFile(jar_path, 'r') as zin:
                    for item in zin.infolist():
                        name = item.filename
                        if name.startswith('META-INF/versions/'):
                            continue
                        for pfx in target_prefixes:
                            if name.endswith(pfx + '.class') or (name.endswith('.class') and (pfx + '$') in name):
                                seen_owner.setdefault(pfx, jar_path)
            except Exception as e:
                print(f"[Sanitize] Scan owner failed for {os.path.basename(jar_path)}: {e}")

        removed_total = 0
        # 第二次扫描并重写：剔除 Multi-Release 目标类，以及非拥有者JAR中的主版本重复类（含内部类）
        for jar_path in keycloak_jars:
            tmp_path = jar_path + '.tmp'
            removed = 0
            rewrote = False
            try:
                with zipfile.ZipFile(jar_path, 'r') as zin, zipfile.ZipFile(tmp_path, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
                    for item in zin.infolist():
                        name = item.filename
                        drop = False
                        for pfx in target_prefixes:
                            # 统一剔除 Multi-Release 路径下的目标类（主类与内部类）
                            if name.startswith('META-INF/versions/'):
                                if name.endswith(pfx + '.class') or ((pfx + '$') in name and name.endswith('.class')):
                                    drop = True
                                    break
                            else:
                                # 主版本跨JAR去重：仅保留首次拥有者，其他JAR删除（主类与内部类）
                                if name.endswith(pfx + '.class') or ((pfx + '$') in name and name.endswith('.class')):
                                    owner = seen_owner.get(pfx)
                                    if owner and owner != jar_path:
                                        drop = True
                                        break
                        if drop:
                            removed += 1
                            rewrote = True
                            continue
                        data = zin.read(item.filename)
                        zout.writestr(item, data)
                if rewrote:
                    _os.replace(tmp_path, jar_path)
                    print(f"[Sanitize] Removed {removed} conflicting entries from {os.path.basename(jar_path)}")
                    removed_total += removed
                else:
                    try:
                        _os.remove(tmp_path)
                    except Exception:
                        pass
            except Exception as e:
                print(f"[Sanitize] Rewrite failed for {os.path.basename(jar_path)}: {e}")
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
        return removed_total


def create_test_realm():
    """Create a minimal test realm configuration"""
    realm_config = {
        "id": "fuzz",
        "realm": "fuzz",
        "displayName": "OAuth Fuzzing Realm",
        "enabled": True,
        "sslRequired": "external",
        "registrationAllowed": False,
        "loginWithEmailAllowed": True,
        "duplicateEmailsAllowed": False,
        "resetPasswordAllowed": True,
        "editUsernameAllowed": False,
        "bruteForceProtected": False,
        "users": [
            {
                "id": "test-user-id",
                "createdTimestamp": 1640995200000,
                "username": "testuser",
                "enabled": True,
                "totp": False,
                "emailVerified": True,
                "firstName": "Test",
                "lastName": "User",
                "email": "testuser@example.com",
                "credentials": [
                    {
                        "id": "test-credential-id",
                        "type": "password",
                        "userLabel": "My password",
                        "value": "testpass",
                        "temporary": False
                    }
                ],
                "disableableCredentialTypes": [],
                "requiredActions": [],
                "realmRoles": ["offline_access", "uma_authorization"],
                "clientRoles": {},
                "notBefore": 0,
                "groups": []
            }
        ],
        "clients": [
            {
                "id": "fuzz-client-id",
                "clientId": "fuzz-client",
                "name": "OAuth Fuzzing Client",
                "description": "Client for OAuth fuzzing tests",
                "rootUrl": "",
                "adminUrl": "",
                "baseUrl": "",
                "surrogateAuthRequired": False,
                "enabled": True,
                "alwaysDisplayInConsole": False,
                "clientAuthenticatorType": "client-secret",
                "secret": "fuzz-client-secret",
                "registrationAccessToken": "",
                "defaultRoles": [],
                "redirectUris": [
                    "http://127.0.0.1:7777/callback",
                    "http://localhost:7777/callback"
                ],
                "webOrigins": [
                    "http://127.0.0.1:7777",
                    "http://localhost:7777"
                ],
                "notBefore": 0,
                "bearerOnly": False,
                "consentRequired": False,
                "standardFlowEnabled": True,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": True,
                "serviceAccountsEnabled": False,
                "publicClient": False,
                "frontchannelLogout": False,
                "protocol": "openid-connect",
                "attributes": {
                    "saml.assertion.signature": "false",
                    "saml.force.post.binding": "false",
                    "saml.multivalued.roles": "false",
                    "saml.encrypt": "false",
                    "saml.server.signature": "false",
                    "saml.server.signature.keyinfo.ext": "false",
                    "exclude.session.state.from.auth.response": "false",
                    "saml_force_name_id_format": "false",
                    "saml.client.signature": "false",
                    "tls.client.certificate.bound.access.tokens": "false",
                    "saml.authnstatement": "false",
                    "display.on.consent.screen": "false",
                    "saml.onetimeuse.condition": "false",
                    "pkce.code.challenge.method": "S256"
                },
                "authenticationFlowBindingOverrides": {},
                "fullScopeAllowed": True,
                "nodeReRegistrationTimeout": -1,
                "defaultClientScopes": [
                    "web-origins",
                    "role_list",
                    "profile",
                    "roles",
                    "email"
                ],
                "optionalClientScopes": [
                    "address",
                    "phone",
                    "offline_access",
                    "microprofile-jwt"
                ],
                "access": {
                    "view": True,
                    "configure": True,
                    "manage": True
                }
            }
        ],
        "roles": {
            "realm": [
                {
                    "id": "offline-access-role-id",
                    "name": "offline_access",
                    "description": "${role_offline-access}",
                    "composite": False,
                    "clientRole": False,
                    "containerId": "fuzz",
                    "attributes": {}
                },
                {
                    "id": "uma-authorization-role-id",
                    "name": "uma_authorization",
                    "description": "${role_uma_authorization}",
                    "composite": False,
                    "clientRole": False,
                    "containerId": "fuzz",
                    "attributes": {}
                }
            ],
            "client": {}
        },
        "defaultGroups": [],
        "clientScopeMappings": {},
        "scopeMappings": [
            {
                "client": "fuzz-client",
                "roles": [
                    "offline_access"
                ]
            }
        ],
        "ssoSessionIdleTimeout": 1800,
        "ssoSessionMaxLifespan": 36000,
        "ssoSessionIdleTimeoutRememberMe": 0,
        "ssoSessionMaxLifespanRememberMe": 0,
        "offlineSessionIdleTimeout": 2592000,
        "offlineSessionMaxLifespanEnabled": False,
        "offlineSessionMaxLifespan": 5184000,
        "clientSessionIdleTimeout": 0,
        "clientSessionMaxLifespan": 0,
        "clientOfflineSessionIdleTimeout": 0,
        "clientOfflineSessionMaxLifespan": 0,
        "accessTokenLifespan": 300,
        "accessTokenLifespanForImplicitFlow": 900,
        "accessCodeLifespan": 60,
        "accessCodeLifespanUserAction": 300,
        "accessCodeLifespanLogin": 1800,
        "actionTokenGeneratedByAdminLifespan": 43200,
        "actionTokenGeneratedByUserLifespan": 300,
        "oauth2DeviceCodeLifespan": 600,
        "oauth2DevicePollingInterval": 5,
        "internationalizationEnabled": False,
        "supportedLocales": [],
        "defaultLocale": "",
        "authenticationFlows": [],
        "authenticatorConfig": [],
        "requiredActions": [],
        "browserFlow": "browser",
        "registrationFlow": "registration",
        "directGrantFlow": "direct grant",
        "resetCredentialsFlow": "reset credentials",
        "clientAuthenticationFlow": "clients",
        "dockerAuthenticationFlow": "docker auth",
        "attributes": {
            "frontendUrl": "",
            "adminTheme": "keycloak",
            "accountTheme": "keycloak",
            "emailTheme": "keycloak",
            "loginTheme": "keycloak",
            "internationalizationEnabled": "false",
            "supportedLocales": [],
            "defaultLocale": ""
        },
        "userManagedAccessAllowed": False,
        "clientProfiles": {
            "profiles": []
        },
        "clientPolicies": {
            "policies": []
        }
    }
    
    # Save realm configuration
    realm_file = "keycloak-fuzz-realm.json"
    try:
        # 先序列化验证JSON格式
        valid_json = json.dumps(realm_config, indent=2)
        with open(realm_file, 'w') as f:
            f.write(valid_json)
        print(f"Created valid realm configuration: {realm_file}")
        
        # 额外验证文件可读性
        with open(realm_file, 'r') as f:
            json.load(f)  # 尝试加载文件，确保可解析
        return realm_file
    except json.JSONDecodeError as e:
        print(f"Realm configuration is invalid JSON: {e}")
        raise
    except Exception as e:
        print(f"Failed to create realm file: {e}")
        raise


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Keycloak manager with JaCoCo')
    parser.add_argument('--config', default='configs/oauth_java_coverage.json', help='Configuration file')
    parser.add_argument('--action', choices=['start', 'stop', 'restart', 'status'], default='start', help='Action to perform')
    
    args = parser.parse_args()
    
    # Load configuration
    with open(args.config, 'r') as f:
        config = json.load(f)
    
    # Create Keycloak manager
    km = KeycloakManager(config)
    
    if args.action == 'start':
        # Create test realm
        realm_file = create_test_realm()
        
        # Start Keycloak
        if km.start_keycloak():
            # Import realm
            km.import_realm(realm_file)
            print("Keycloak is ready for fuzzing!")
        else:
            print("Failed to start Keycloak")
            sys.exit(1)
    
    elif args.action == 'stop':
        km.stop_keycloak()
    
    elif args.action == 'restart':
        km.stop_keycloak()
        time.sleep(5)
        km.start_keycloak()
    
    elif args.action == 'status':
        try:
            response = requests.get(km.health_check_url, timeout=5)
            if response.status_code == 200:
                print("Keycloak is running")
            else:
                print(f"Keycloak returned status {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Keycloak is not accessible: {e}")


if __name__ == "__main__":
    main()

