#!/usr/bin/env python3
"""Coverage data structures and JaCoCo toolchain management."""

import subprocess
import os
import re
import zipfile
import requests
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass
class CoverageData:
    """Coverage data structure"""
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

@dataclass
class GranularCoverageData(CoverageData):
    """细粒度覆盖率数据结构"""
    # 新增模块级覆盖率
    module_coverage: Dict[str, float] = None
    # 新增热点方法跟踪
    hot_methods: Set[str] = None
    # NEW: Security-relevant path tracking
    security_paths_covered: Set[str] = None
    # NEW: OAuth endpoint coverage tracking
    oauth_endpoint_coverage: Dict[str, int] = None

    def __post_init__(self):
        if self.module_coverage is None:
            self.module_coverage = {}
        if self.hot_methods is None:
            self.hot_methods = set()
        if self.security_paths_covered is None:
            self.security_paths_covered = set()
        if self.oauth_endpoint_coverage is None:
            self.oauth_endpoint_coverage = {}

    def probe_fingerprint(self) -> frozenset:
        """Return a frozen set uniquely identifying the execution footprint.

        Used by the fuzzer to detect per-iteration novelty when cumulative
        coverage percentage has saturated. Combines hot methods with
        coarse module-level counters so newly-entered modules register as
        novelty even before a method crosses the 70% hot threshold.
        """
        probe_items = set(self.hot_methods)
        for mod, pct in (self.module_coverage or {}).items():
            # Bucket module % into 10% slices so we register transitions
            # (e.g. 13% -> 24% will change the fingerprint; 13% -> 17% will not).
            probe_items.add(f"__mod__:{mod}:{int(pct) // 10}")
        # Include coarse branch and instruction buckets to catch
        # gains that don't yet promote any method to "hot".
        probe_items.add(f"__branches__:{self.branches_covered // 50}")
        probe_items.add(f"__instr__:{self.instructions_covered // 200}")
        return frozenset(probe_items)

class JaCoCoManager:
    """
    Complete JaCoCo toolchain manager
    Handles agent download, setup, and report generation
    """
    
    def __init__(self, work_dir: str = "jacoco_tools", version: Optional[str] = None):
        self.work_dir = os.path.abspath(work_dir)
        self.jacoco_version = version or "0.8.14"
        self.agent_jar = "jacocoagent.jar"  
        self.cli_jar = "jacococli.jar"      
        self.coverage_file = None
        self.report_dir = os.path.join(self.work_dir, "reports")
        self.classpaths: List[str] = []
        self._version_marker = os.path.join(work_dir, "jacoco.version")
        
        # Ensure directories exist
        os.makedirs(work_dir, exist_ok=True)
        os.makedirs(self.report_dir, exist_ok=True)
        
        # Download tools if not present
        self._download_and_extract_tools()

    def get_agent_args(self, port: int = 6300, includes: Optional[List[str]] = None, excludes: Optional[List[str]] = None) -> List[str]:
        agent_path = "/opt/jacoco/" + self.agent_jar
        self.coverage_file = os.path.join(self.work_dir, "coverage.exec")
        inc = includes or ['*']
        exc = excludes or []
        inc_str = ":".join(inc)
        exc_str = ":".join(exc) if exc else ""
        opts = f"output=tcpserver,address=0.0.0.0,port={port},includes={inc_str}"
        if exc_str:
            opts += f",excludes={exc_str}"
        return [f"-javaagent:{agent_path}={opts}"]
    
    def _download_and_extract_tools(self):
        """下载JaCoCo zip包并提取所需jar文件（带版本标记）
        
        支持离线模式：优先从本地ZIP文件提取，网络不可用时自动降级
        """
        zip_filename = f"jacoco-{self.jacoco_version}.zip"
        zip_path = os.path.join(self.work_dir, zip_filename)
        agent_path = os.path.join(self.work_dir, self.agent_jar)
        cli_path = os.path.join(self.work_dir, self.cli_jar)

        # 检查是否已有可用工具
        if os.path.exists(agent_path) and os.path.exists(cli_path):
            print(f"[JaCoCo] 工具已存在，跳过初始化")
            # 更新版本标记
            try:
                with open(self._version_marker, 'w') as vf:
                    vf.write(self.jacoco_version)
            except Exception:
                pass
            return

        # 清理旧文件
        for p in (agent_path, cli_path):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass
        
        # 策略1: 优先从本地ZIP文件提取（离线模式）
        if os.path.exists(zip_path):
            print(f"[JaCoCo] 从本地ZIP提取: {zip_filename}")
            try:
                self._extract_from_zip(zip_path, agent_path, cli_path)
                return
            except Exception as e:
                print(f"[JaCoCo] 本地提取失败: {e}")
        
        # 策略2: 尝试其他本地ZIP版本（版本兼容模式）
        alt_versions = ["0.8.14", "0.8.9", "0.8.11", "0.8.13", "0.8.15"]
        for alt_ver in alt_versions:
            if alt_ver == self.jacoco_version:
                continue
            alt_zip = os.path.join(self.work_dir, f"jacoco-{alt_ver}.zip")
            if os.path.exists(alt_zip):
                print(f"[JaCoCo] 尝试备用版本: {alt_ver}")
                try:
                    self._extract_from_zip(alt_zip, agent_path, cli_path)
                    # 更新版本标记为实际使用的版本
                    try:
                        with open(self._version_marker, 'w') as vf:
                            vf.write(alt_ver)
                    except Exception:
                        pass
                    return
                except Exception as e:
                    print(f"[JaCoCo] 备用版本 {alt_ver} 提取失败: {e}")
        
        # 策略3: 尝试网络下载（在线模式）
        base_url = f"https://repo1.maven.org/maven2/org/jacoco/jacoco/{self.jacoco_version}"
        zip_url = f"{base_url}/{zip_filename}"
        
        try:
            print(f"[JaCoCo] 尝试下载: {zip_url}")
            self._download_file(zip_url, zip_path)
            self._extract_from_zip(zip_path, agent_path, cli_path)
            return
        except Exception as e:
            print(f"[JaCoCo] 下载失败: {e}")
        
        # 所有策略都失败
        available_zips = [f for f in os.listdir(self.work_dir) if f.startswith('jacoco-') and f.endswith('.zip')]
        raise FileNotFoundError(
            f"无法获取 JaCoCo 工具。请确保以下文件之一存在：\n"
            f"  - {zip_path}\n"
            f"  或以下备用版本: {', '.join([f'jacoco-{v}.zip' for v in alt_versions])}\n"
            f"当前目录中的ZIP文件: {available_zips if available_zips else '(无)'}\n"
            f"手动下载命令: wget {zip_url} -O {zip_path}"
        )
    
    def _extract_from_zip(self, zip_path: str, agent_path: str, cli_path: str):
        """从ZIP文件提取JaCoCo工具"""
        print(f"[JaCoCo] 正在解压: {os.path.basename(zip_path)}")
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # 查找JAR文件（可能在不同路径）
            agent_found = False
            cli_found = False
            
            for file in zip_ref.namelist():
                if file.endswith(self.agent_jar) and not agent_found:
                    zip_ref.extract(file, self.work_dir)
                    extracted_path = os.path.join(self.work_dir, file)
                    # 处理嵌套目录
                    if os.path.dirname(file):
                        # 文件在子目录中，移动到根目录
                        os.replace(extracted_path, agent_path)
                        # 清理空目录
                        try:
                            os.removedirs(os.path.dirname(extracted_path))
                        except:
                            pass
                    else:
                        os.replace(extracted_path, agent_path)
                    agent_found = True
                    print(f"[JaCoCo] 提取: {self.agent_jar}")
                    
                elif file.endswith(self.cli_jar) and not cli_found:
                    zip_ref.extract(file, self.work_dir)
                    extracted_path = os.path.join(self.work_dir, file)
                    # 处理嵌套目录
                    if os.path.dirname(file):
                        os.replace(extracted_path, cli_path)
                        try:
                            os.removedirs(os.path.dirname(extracted_path))
                        except:
                            pass
                    else:
                        os.replace(extracted_path, cli_path)
                    cli_found = True
                    print(f"[JaCoCo] 提取: {self.cli_jar}")
        
        if not os.path.exists(agent_path) or not os.path.exists(cli_path):
            raise FileNotFoundError(
                f"ZIP中未找到所需JAR文件: {self.agent_jar}, {self.cli_jar}"
            )
        
        # 写版本标记
        try:
            with open(self._version_marker, 'w') as vf:
                # 从ZIP文件名提取版本
                zip_name = os.path.basename(zip_path)
                version = zip_name.replace('jacoco-', '').replace('.zip', '')
                vf.write(version)
        except Exception:
            pass
        
        print("[JaCoCo] 工具提取成功")

    def _download_file(self, url: str, filepath: str, timeout: int = 30):
        """Download file from URL with timeout and better error handling"""
        try:
            # 设置较短的超时，快速失败
            response = requests.get(url, stream=True, timeout=(5, timeout))
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        # 可选：显示下载进度
                        if total_size > 0 and downloaded % (1024 * 1024) == 0:  # 每1MB
                            percent = (downloaded / total_size) * 100
                            print(f"[JaCoCo] 下载进度: {percent:.1f}%")
            
            print(f"[JaCoCo] 下载完成: {filepath}")
            
        except requests.exceptions.Timeout:
            raise ConnectionError(f"下载超时 ({timeout}s): {url}")
        except requests.exceptions.ConnectionError as e:
            raise ConnectionError(f"网络连接失败: {url} - {e}")
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"下载失败: {url} - {e}")
        except Exception as e:
            raise ConnectionError(f"下载异常: {url} - {e}")

    def generate_report(self) -> Optional[str]:
        """Generate a JaCoCo XML report from the cumulative exec file."""
        if not self.classpaths:
            print("[JaCoCo] No classpaths configured; cannot generate report")
            return None
        exec_file = os.path.join(self.work_dir, "coverage.exec")
        if not os.path.exists(exec_file):
            print(f"[JaCoCo] No exec file at {exec_file}")
            return None

        # Guard: refuse to generate a report from a pathologically large exec
        # file. Historical 50 MB threshold was calibrated for Keycloak
        # (~800 instrumented classes). WSO2 IS loads ~2500 classes once its
        # OSGi runtime warms up, so a healthy exec file is 150-350 MB. Apply
        # a target-aware ceiling so WSO2 dumps are not systematically
        # refused.
        try:
            exec_size = os.path.getsize(exec_file)
            # Allow callers to override via attribute; default 50 MB.
            max_exec_mb = getattr(self, 'max_exec_mb', 50)
            if exec_size > max_exec_mb * 1024 * 1024:
                print(f"[JaCoCo] WARNING: exec file is {exec_size // (1024*1024)} MB "
                      f"(threshold {max_exec_mb} MB) — refusing to generate report "
                      f"(would produce multi-GB XML). Delete and re-dump.")
                return None
        except Exception:
            pass

        cli_path = os.path.join(self.work_dir, self.cli_jar)
        xml_report = os.path.join(self.report_dir, "coverage.xml")

        cmd = [
            "java", "-jar", cli_path, "report",
            exec_file,
            "--xml", xml_report
        ]
        for cp in self.classpaths:
            if os.path.exists(cp):
                cmd.extend(["--classfiles", cp])

        try:
            print(f"[JaCoCo] Running report command with {len(self.classpaths)} classpaths")
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            if os.path.exists(xml_report):
                print(f"[JaCoCo] Report generated: {xml_report} (size={os.path.getsize(xml_report)})")
            return xml_report
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or ''
            print(f"[JaCoCo] Report generation FAILED!")
            print(f"[JaCoCo] Command: {' '.join(cmd[:6])}... ({len(cmd)} args)")
            print(f"[JaCoCo] Return code: {e.returncode}")
            print(f"[JaCoCo] STDERR: {stderr[:2000] if stderr else 'N/A'}")
            print(f"[JaCoCo] STDOUT: {e.stdout[:1000] if e.stdout else 'N/A'}")

            # Actionable diagnostic for the most common mis‑configuration:
            # duplicate‑FQN across classpaths. This used to surface as
            # `Can't add different class with same name: …` on WSO2 when
            # Axis2 stub bundles were passed to --classfiles. The real
            # fix lives in the target manager (blacklist stubs + unify
            # into a single classes/ tree); this message points operators
            # at it immediately.
            if "Can't add different class with same name" in stderr:
                import re
                m = re.search(r"same name:\s*([^\s]+\.class)", stderr)
                fqn = m.group(1) if m else '<unknown>'
                print(f"[JaCoCo] DUPLICATE FQN detected: {fqn}")
                print(f"[JaCoCo]   This means two .class files with the same "
                      f"fully-qualified name but different bytecode were passed "
                      f"to --classfiles.")
                print(f"[JaCoCo]   Common root cause: WSDL→Java stub bundles "
                      f"(*.stub_*.jar) re-generating shared XSD classes.")
                print(f"[JaCoCo]   Fix: blacklist stubs in _prepare_classpaths() "
                      f"and unpack residual jars into ONE unified classes/ tree "
                      f"(first-writer-wins).")

            try:
                if os.path.exists(xml_report):
                    sz = os.path.getsize(xml_report)
                    if sz == 0 or sz > 200 * 1024 * 1024:
                        os.remove(xml_report)
                        print(f"[JaCoCo] Removed partial/oversized report ({sz} bytes)")
            except Exception:
                pass
            return None
    
    def parse_granular_coverage_xml(self, xml_file: str) -> GranularCoverageData:
        """解析细粒度覆盖率XML报告"""
        if not os.path.exists(xml_file):
            return GranularCoverageData()
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            coverage = GranularCoverageData()
            
            # 包级覆盖率聚合 + 总体计数（按类级counter）
            for package in root.findall('.//package'):
                package_name = package.get('name', '')
                pkg_instr_cov = 0
                pkg_instr_total = 0

                for cls in package.findall('.//class'):
                    for c in cls.findall('counter'):
                        ctype = c.get('type', '')
                        covered = int(c.get('covered', 0))
                        missed = int(c.get('missed', 0))
                        total = covered + missed
                        if ctype == 'INSTRUCTION':
                            pkg_instr_cov += covered
                            pkg_instr_total += total
                            coverage.instructions_covered += covered
                            coverage.instructions_total += total
                        elif ctype == 'BRANCH':
                            coverage.branches_covered += covered
                            coverage.branches_total += total
                        elif ctype == 'LINE':
                            coverage.lines_covered += covered
                            coverage.lines_total += total
                        elif ctype == 'METHOD':
                            coverage.methods_covered += covered
                            coverage.methods_total += total
                        elif ctype == 'CLASS':
                            coverage.classes_covered += covered
                            coverage.classes_total += total

                if pkg_instr_total > 0:
                    coverage.module_coverage[package_name] = (pkg_instr_cov / pkg_instr_total) * 100
            
            # 热点方法识别
            for cls in root.findall('.//class'):
                class_name = cls.get('name', '')
                for method in cls.findall('.//method'):
                    mc = method.find('counter[@type="INSTRUCTION"]')
                    if mc is not None:
                        covered = int(mc.get('covered', 0))
                        missed = int(mc.get('missed', 0))
                        total = covered + missed
                        if total > 0 and (covered / total) > 0.7:
                            coverage.hot_methods.add(f"{class_name}.{method.get('name', '')}")
            
            if coverage.instructions_total > 0:
                coverage.coverage_percentage = (coverage.instructions_covered / coverage.instructions_total) * 100

            # 诊断输出
            try:
                print(f"[Coverage] Granular totals: instr={coverage.instructions_covered}/{coverage.instructions_total}, "
                      f"lines={coverage.lines_covered}/{coverage.lines_total}, branches={coverage.branches_covered}/{coverage.branches_total}, "
                      f"methods={coverage.methods_covered}/{coverage.methods_total}, classes={coverage.classes_covered}/{coverage.classes_total}, "
                      f"percent={coverage.coverage_percentage:.2f}%")
            except Exception:
                pass

            return coverage
        except ET.ParseError as e:
            print(f"Failed to parse coverage XML: {e}")
            return GranularCoverageData()
        except Exception as e:
            print(f"Error parsing coverage: {e}")
            return GranularCoverageData()

    def set_classpaths(self, paths: List[str]) -> None:
        """Set classpaths (directories or jars) used by jacococli report"""
        try:
            self.classpaths = [os.path.abspath(p) for p in (paths or [])]
        except Exception:
            self.classpaths = paths or []

    def exec_info(self) -> Optional[Dict]:
        """
        Analyze the exec file contents using jacococli execinfo.
        Returns dict with session info, class count, and class ID details.
        """
        exec_path = os.path.join(self.work_dir, "coverage.exec")
        if not os.path.exists(exec_path):
            print("[JaCoCo] No coverage.exec found for analysis")
            return None

        cli_path = os.path.join(self.work_dir, self.cli_jar)
        if not os.path.exists(cli_path):
            print("[JaCoCo] CLI jar not found")
            return None

        try:
            cmd = ["java", "-jar", cli_path, "execinfo", exec_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"[JaCoCo] execinfo failed: {result.stderr[:500]}")
                return None

            output = result.stdout
            info = {
                'raw_output': output,
                'sessions': [],
                'classes': [],
                'class_count': 0,
                'total_probes': 0,
            }

            import re
            class_ids = {}

            for line in output.splitlines():
                stripped = line.strip()
                if stripped.startswith('Session'):
                    info['sessions'].append(stripped)
                elif stripped.startswith('CLASS ID') or stripped.startswith('['):
                    continue
                else:
                    # JaCoCo execinfo format: "%016x  %3d of %3d   %s"
                    # e.g.: de45942e0bafb839    1 of   5   org/springframework/security/oauth2/server/authorization/OAuth2AuthorizationService
                    m = re.match(r'^([0-9a-f]{16})\s+\d+\s+of\s+\d+\s+(\S+)', stripped)
                    if m:
                        class_ids[m.group(2)] = m.group(1)
                        info['classes'].append(stripped)

            info['class_count'] = len(class_ids)
            info['class_ids'] = class_ids

            return info

        except Exception as e:
            print(f"[JaCoCo] execinfo exception: {e}")
            return None

    def compute_classpath_class_ids(self) -> Dict[str, str]:
        """
        Compute CRC64 class IDs for all classes in the configured classpaths.
        Uses jacococli classinfo to compute IDs matching the exec format.
        """
        cli_path = os.path.join(self.work_dir, self.cli_jar)
        if not os.path.exists(cli_path):
            return {}

        all_class_ids = {}
        import re

        for cp in self.classpaths:
            if not os.path.exists(cp):
                continue
            try:
                cmd = ["java", "-jar", cli_path, "classinfo", cp]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if result.returncode == 0:
                    # JaCoCo classinfo format per line:
                    # "   NNN    NNN    NNN    NNN    NNN   class 0xDEADBEEF12345678 org/springframework/security/oauth2/server/authorization/Foo"
                    for line in result.stdout.splitlines():
                        m = re.search(r'class\s+0x([0-9a-f]{16})\s+(\S+)', line)
                        if m:
                            all_class_ids[m.group(2)] = m.group(1)
            except Exception:
                pass

        return all_class_ids

    def dump_coverage(self, address: str = "127.0.0.1", port: int = 6300) -> bool:
        """Online mode: dump current coverage via JaCoCo tcpserver into coverage.exec."""
        try:
            dest = os.path.join(self.work_dir, "coverage.exec")
            cli_path = os.path.join(self.work_dir, self.cli_jar)
            tmp_override = os.environ.get('OAUTH_FUZZ_JVM_TMPDIR') or os.environ.get('AFLNET_JVM_TMPDIR') or os.path.join(self.work_dir, 'jvm_tmp')
            try:
                os.makedirs(tmp_override, exist_ok=True)
            except Exception:
                pass
            cmd = [
                "java", f"-Djava.io.tmpdir={tmp_override}",
                "-jar", cli_path, "dump",
                "--address", address,
                "--port", str(port),
                "--destfile", dest
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            ok = (result.returncode == 0) and os.path.exists(dest) and os.path.getsize(dest) > 0
            if not ok:
                print(f"[JaCoCo] Dump failed: returncode={result.returncode}, dest_exists={os.path.exists(dest)}")
                if result.stderr:
                    print(f"[JaCoCo] Dump STDERR: {result.stderr[:500]}")
            self.coverage_file = dest if ok else None
            return ok
        except subprocess.TimeoutExpired:
            print(f"[JaCoCo] Dump timed out after 30s (agent may be unresponsive)")
            return False
        except Exception as e:
            print(f"[JaCoCo] dump exception: {e}")
            return False

    def dump_coverage_reset(self, address: str = "127.0.0.1", port: int = 6300) -> bool:
        """Dump current coverage AND reset JaCoCo probes for differential tracking.
        
        This enables true coverage-guided fuzzing by measuring per-iteration gains
        rather than cumulative coverage that saturates at the baseline.
        """
        try:
            dest = os.path.join(self.work_dir, "coverage.exec")
            cli_path = os.path.join(self.work_dir, self.cli_jar)
            cmd = [
                "java", "-jar", cli_path, "dump",
                "--address", address,
                "--port", str(port),
                "--destfile", dest,
                "--reset"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            ok = (result.returncode == 0) and os.path.exists(dest) and os.path.getsize(dest) > 0
            if not ok:
                print(f"[JaCoCo] Dump+reset failed: rc={result.returncode}")
                if result.stderr:
                    print(f"[JaCoCo] Dump STDERR: {result.stderr[:500]}")
            self.coverage_file = dest if ok else None
            return ok
        except Exception as e:
            print(f"[JaCoCo] dump_reset exception: {e}")
            return False

    def merge_exec_files(self, exec_files: list, dest: str = None) -> str:
        """Merge multiple .exec files into one cumulative exec for accurate totals."""
        dest = dest or os.path.join(self.work_dir, "coverage_merged.exec")
        cli_path = os.path.join(self.work_dir, self.cli_jar)
        cmd = ["java", "-jar", cli_path, "merge"]
        for f in exec_files:
            if os.path.exists(f):
                cmd.append(f)
        cmd.extend(["--destfile", dest])
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0 and os.path.exists(dest):
                return dest
        except Exception as e:
            print(f"[JaCoCo] Merge failed: {e}")
        return None

    def parse_coverage_xml(self, xml_file: str) -> CoverageData:
        """Parse JaCoCo XML to basic CoverageData"""
        if not os.path.exists(xml_file):
            return CoverageData()
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            cov = CoverageData()
            # 按类级counter聚合
            for cls in root.findall('.//class'):
                for c in cls.findall('counter'):
                    ctype = c.get('type')
                    covered = int(c.get('covered', 0))
                    missed = int(c.get('missed', 0))
                    total = covered + missed
                    if ctype == 'INSTRUCTION':
                        cov.instructions_covered += covered
                        cov.instructions_total += total
                    elif ctype == 'BRANCH':
                        cov.branches_covered += covered
                        cov.branches_total += total
                    elif ctype == 'LINE':
                        cov.lines_covered += covered
                        cov.lines_total += total
                    elif ctype == 'METHOD':
                        cov.methods_covered += covered
                        cov.methods_total += total
                    elif ctype == 'CLASS':
                        cov.classes_covered += covered
                        cov.classes_total += total

            # 兜底：若类级仍为0，尝试根级counter
            if cov.instructions_total == 0:
                for counter in root.findall('counter'):
                    ctype = counter.get('type')
                    covered = int(counter.get('covered', 0))
                    missed = int(counter.get('missed', 0))
                    total = covered + missed
                    if ctype == 'INSTRUCTION':
                        cov.instructions_covered += covered
                        cov.instructions_total += total
                    elif ctype == 'BRANCH':
                        cov.branches_covered += covered
                        cov.branches_total += total
                    elif ctype == 'LINE':
                        cov.lines_covered += covered
                        cov.lines_total += total
                    elif ctype == 'METHOD':
                        cov.methods_covered += covered
                        cov.methods_total += total
                    elif ctype == 'CLASS':
                        cov.classes_covered += covered
                        cov.classes_total += total

            if cov.instructions_total > 0:
                cov.coverage_percentage = (cov.instructions_covered / cov.instructions_total) * 100

            # 诊断输出（遵循规范）
            try:
                print(f"[Coverage] Basic totals: instr={cov.instructions_covered}/{cov.instructions_total}, "
                      f"lines={cov.lines_covered}/{cov.lines_total}, branches={cov.branches_covered}/{cov.branches_total}, "
                      f"methods={cov.methods_covered}/{cov.methods_total}, classes={cov.classes_covered}/{cov.classes_total}, "
                      f"percent={cov.coverage_percentage:.2f}%")
            except Exception:
                pass

            return cov
        except Exception as e:
            print(f"Error parsing basic coverage: {e}")
            return CoverageData()