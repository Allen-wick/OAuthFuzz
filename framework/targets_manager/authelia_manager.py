#!/usr/bin/env python3
"""
Authelia Manager for OAuth Fuzzing Framework
Manages Authelia (Go-based OAuth/OIDC provider) lifecycle and operations.

Authelia is a Go-based authentication server that provides OAuth2/OIDC capabilities.
Unlike Keycloak (Java), it doesn't support JaCoCo for coverage collection.
"""

import subprocess
import time
import requests
import json
import os
import sys
import shutil
from typing import Dict, Optional, List
from targets_manager.base import TargetManager
from core.paths import PROJECT_ROOT


class AutheliaManager(TargetManager):
    """
    Authelia server manager for OAuth fuzzing.
    
    Authelia is a Go-based OIDC provider that uses file-based configuration.
    Coverage collection requires Go's built-in coverage or external tools (not JaCoCo).
    """
    
    def __init__(self, config: Dict):
        super().__init__(config)  # base init: _atexit_registered etc.
        self.config = config
        self.process = None
        
        # Base URL configuration
        authelia_cfg = config.get('authelia', {})
        oauth_cfg = config.get('oauth', {})
        
        self.base_url = oauth_cfg.get('base_url', 'http://127.0.0.1:9091')
        self.container_name = authelia_cfg.get('container_name', 'authelia-fuzz')
        self.image = authelia_cfg.get('image', 'authelia/authelia:latest')
        
        # Configuration directories
        self.config_dir = os.path.abspath(authelia_cfg.get('config_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'authelia_service', 'config')))
        self.work_dir = os.path.abspath(authelia_cfg.get('work_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'authelia_service', 'work')))
        
        # Health check endpoint
        self.health_check_url = authelia_cfg.get(
            'health_check_url', 
            f'{self.base_url}/api/health'
        )
        
        # Ports
        self.http_port = authelia_cfg.get('http_port', 9091)
        self.metrics_port = authelia_cfg.get('metrics_port', 9959)
        
        # Coverage support (Go-based)
        self.coverage_enabled = authelia_cfg.get('coverage_enabled', False)
        self.coverage_dir = os.path.abspath(authelia_cfg.get('coverage_dir', os.path.join(PROJECT_ROOT, 'targets_manager', 'authelia_service', 'coverage')))
        
        # Initialize Go coverage manager
        try:
            from targets_manager.go_coverage_manager import GoCoverageManager
            self.go_coverage = GoCoverageManager(work_dir=self.coverage_dir)
            if self.coverage_enabled:
                print(f"[GoCoverage] Enabled for Authelia")
            else:
                print(f"[GoCoverage] State-based tracking enabled for Authelia")
        except ImportError as e:
            print(f"[GoCoverage] go_coverage_manager.py not found: {e}")
            self.go_coverage = None
        
        # Placeholder for compatibility with fuzzer expecting jacoco attribute
        self.jacoco = None
        
    def start(self) -> bool:
        """Start Authelia container"""
        return self.start_authelia()
    
    def stop(self) -> None:
        """Stop Authelia container"""
        self.stop_authelia()
    
    def start_authelia(self) -> bool:
        """Start Authelia with proper configuration"""
        print("=" * 60)
        print("Starting Authelia (Go-based OAuth/OIDC provider)...")
        print("=" * 60)
        
        # Cleanup existing container
        self._cleanup_container()
        
        # Prepare configuration directories
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.work_dir, exist_ok=True)
        
        # Generate Authelia configuration files
        if not self._generate_configuration():
            print("Failed to generate Authelia configuration")
            return False
        
        # Generate secrets
        self._generate_secrets()
        
        # Build Docker command
        cmd = self._build_docker_command()
        
        try:
            print(f"Starting container with command: {' '.join(cmd[:10])}...")
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            container_id = result.stdout.strip()
            print(f"Authelia container started: {container_id}")
            
            # Wait for service readiness
            if not self._wait_for_authelia():
                print("Authelia failed to start properly")
                self._print_container_logs(tail=100)
                return False
            
            print("Authelia is ready for fuzzing!")
            return True
            
        except subprocess.CalledProcessError as e:
            print(f"Failed to start Authelia: {e}")
            print(f"STDERR: {e.stderr}")
            return False
    
    def stop_authelia(self) -> None:
        """Stop Authelia container"""
        print("Stopping Authelia...")
        try:
            # Check if container exists
            chk = subprocess.run(
                ['docker', 'ps', '-aq', '--filter', f'name={self.container_name}'],
                check=True, capture_output=True, text=True
            )
            cid = (chk.stdout or '').strip()
            if not cid:
                print("Authelia container not running; skip stop.")
                return
            
            subprocess.run(
                ['docker', 'stop', self.container_name],
                check=True, capture_output=True, text=True
            )
            print("Authelia stopped")
        except subprocess.CalledProcessError as e:
            print(f"Failed to stop Authelia: {e}")
    
    def is_healthy(self) -> bool:
        """Check if Authelia is healthy"""
        try:
            # Disable SSL verification for self-signed cert
            resp = requests.get(self.health_check_url, timeout=5, verify=False)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    return data.get('status') == 'OK'
                except json.JSONDecodeError:
                    return True
            return False
        except requests.exceptions.RequestException:
            return False
    
    def import_config(self, config_file: str = None) -> bool:
        """
        Import configuration for Authelia.
        
        Unlike Keycloak's API-based import, Authelia uses file-based configuration.
        Configuration is already set up during start_authelia().
        """
        print("Authelia configuration imported via configuration files")
        return True
    
    def _cleanup_container(self) -> None:
        """Remove existing container and clean work directory for fresh start"""
        try:
            subprocess.run(
                ['docker', 'rm', '-f', self.container_name],
                capture_output=True, text=True
            )
            print("Cleaned up existing Authelia container")
        except subprocess.CalledProcessError:
            pass
        
        # Clean up work directory to avoid encryption key mismatch
        # The database is encrypted with the storage.encryption_key, which is
        # regenerated on each start. Keeping old database causes mismatch errors.
        if os.path.exists(self.work_dir):
            try:
                for item in os.listdir(self.work_dir):
                    item_path = os.path.join(self.work_dir, item)
                    if os.path.isfile(item_path):
                        os.remove(item_path)
                    elif os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                print(f"Cleaned work directory: {self.work_dir}")
            except Exception as e:
                print(f"Warning: Could not clean work directory: {e}")
    
    def _build_docker_command(self) -> List[str]:
        """Build Docker run command for Authelia"""
        cmd = [
            'docker', 'run', '-d',
            '--name', self.container_name,
            '-p', f'{self.http_port}:9091',
            '-p', f'{self.metrics_port}:9959',
            '-v', f'{self.config_dir}:/config:ro',
            '-v', f'{self.work_dir}:/data',
            '-e', 'TZ=UTC',
            '-e', 'X_AUTHELIA_CONFIG_FILTERS=template',
        ]
        
        # Add Go coverage environment and volumes if enabled
        if self.coverage_enabled and self.go_coverage:
            coverage_env = self.go_coverage.setup_coverage_environment()
            for key, value in coverage_env.items():
                cmd.extend(['-e', f'{key}={value}'])
            coverage_volumes = self.go_coverage.get_docker_volume_mounts()
            cmd.extend(coverage_volumes)
        
        # Add extra environment variables from config
        env_vars = self.config.get('authelia', {}).get('environment', {})
        for key, value in env_vars.items():
            cmd.extend(['-e', f'{key}={value}'])
        
        cmd.append(self.image)
        cmd.extend(['authelia', '--config', '/config/configuration.yml'])
        
        return cmd
    
    def _wait_for_authelia(self, timeout: int = 120) -> bool:
        """Wait for Authelia to be ready"""
        print(f"Waiting for Authelia to be ready (timeout: {timeout}s)...")
        
        # Suppress SSL warnings for self-signed cert
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        start = time.time()
        interval = 2
        
        while time.time() - start < timeout:
            # First check if container is still running
            try:
                chk = subprocess.run(
                    ['docker', 'ps', '-q', '--filter', f'name={self.container_name}'],
                    capture_output=True, text=True
                )
                if not chk.stdout.strip():
                    print("\n[ERROR] Container exited unexpectedly!")
                    try:
                        logs = subprocess.run(
                            ['docker', 'logs', self.container_name],
                            capture_output=True, text=True
                        )
                        print("=== Container exit logs ===")
                        print(logs.stdout)
                        print(logs.stderr)
                    except Exception:
                        pass
                    return False
            except Exception:
                pass
            
            # Then check health endpoint (with SSL verification disabled)
            try:
                resp = requests.get(self.health_check_url, timeout=5, verify=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data.get('status') == 'OK':
                            print("\nAuthelia health check passed")
                            return True
                    except json.JSONDecodeError:
                        print("\nAuthelia responding (no JSON health)")
                        return True
            except requests.exceptions.RequestException:
                pass
            
            elapsed = int(time.time() - start)
            if elapsed % 10 == 0 and elapsed > 0:
                print(f"  Still waiting... ({elapsed}s elapsed)")
            
            time.sleep(interval)
            interval = min(interval * 1.1, 5)
        
        return False
    
    def _print_container_logs(self, tail: int = 50) -> None:
        """Print container logs for debugging"""
        try:
            logs = subprocess.run(
                ['docker', 'logs', '--tail', str(tail), self.container_name],
                capture_output=True, text=True
            )
            print(f"=== Authelia logs (last {tail} lines) ===")
            print(logs.stdout)
            if logs.stderr:
                print("=== STDERR ===")
                print(logs.stderr)
        except Exception as e:
            print(f"Failed to get logs: {e}")
    
    def _generate_configuration(self) -> bool:
        """Generate Authelia configuration files"""
        try:
            oauth_cfg = self.config.get('oauth', {})
            authelia_cfg = self.config.get('authelia', {})
            
            # Main configuration
            config_yml = self._build_main_config(oauth_cfg, authelia_cfg)
            
            # Write configuration.yml
            config_path = os.path.join(self.config_dir, 'configuration.yml')
            self._write_yaml(config_path, config_yml)
            print(f"Generated: {config_path}")
            
            # Generate users database
            users_yml = self._build_users_database(oauth_cfg)
            users_path = os.path.join(self.config_dir, 'users_database.yml')
            self._write_yaml(users_path, users_yml)
            print(f"Generated: {users_path}")
            
            return True
            
        except Exception as e:
            print(f"Failed to generate configuration: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _build_main_config(self, oauth_cfg: Dict, authelia_cfg: Dict) -> Dict:
        """Build main Authelia configuration for 4.38+ with security testing options"""
        client_id = oauth_cfg.get('client_id', 'fuzz-client')
        client_secret = oauth_cfg.get('client_secret', 'fuzz-client-secret')
        redirect_uri = oauth_cfg.get('redirect_uri', 'https://127.0.0.1:7777/callback')
        
        # Generate secrets
        try:
            import secrets as sec_module
            session_secret = sec_module.token_hex(32)
            storage_key = sec_module.token_hex(32)
            hmac_secret = sec_module.token_hex(32)
            jwt_secret = sec_module.token_hex(32)
        except ImportError:
            session_secret = 'b' * 64
            storage_key = 'c' * 64
            hmac_secret = 'd' * 64
            jwt_secret = 'e' * 64
        
        # Read the PEM key content (not file path!)
        oidc_key_content = self._read_oidc_private_key()
        
        # Use plaintext hash format for client secret (Authelia supports this for testing)
        # The $plaintext$ prefix is accepted by Authelia for development/testing
        hashed_secret = self._hash_client_secret(client_secret)
        
        # Support 2FA testing if enabled
        enable_2fa = authelia_cfg.get('enable_2fa_testing', False)
        default_policy = 'two_factor' if enable_2fa else 'one_factor'
        
        # NEW: Security testing configuration options
        security_testing_mode = authelia_cfg.get('security_testing_mode', False)
        
        # Regulation settings for rate limiting testing
        regulation_config = {
            'max_retries': authelia_cfg.get('max_retries', 10),
            'find_time': authelia_cfg.get('find_time', '2m'),
            'ban_time': authelia_cfg.get('ban_time', '5m')
        }
        
        # If security testing mode, relax some restrictions for testing
        if security_testing_mode:
            regulation_config['max_retries'] = 50
            regulation_config['find_time'] = '30m'
        
        return {
            'theme': 'light',
            
            'server': {
                'address': 'tcp://0.0.0.0:9091/',
                'buffers': {
                    'read': authelia_cfg.get('read_buffer', 4096),
                    'write': authelia_cfg.get('write_buffer', 4096)
                },
                'timeouts': {
                    'read': '6s',
                    'write': '6s',
                    'idle': '30s'
                },
                'endpoints': {
                    'enable_pprof': authelia_cfg.get('enable_pprof', False),
                    'enable_expvars': authelia_cfg.get('enable_expvars', False)
                },
                'disable_healthcheck': False,
                # Enable TLS with self-signed certificate
                'tls': {
                    'key': '/config/server.key',
                    'certificate': '/config/server.crt'
                }
            },
            
            'log': {
                'level': authelia_cfg.get('log_level', 'debug'),
                'format': 'text',
                'file_path': '/data/authelia.log',
                'keep_stdout': True
            },
            
            'totp': {
                'disable': False,
                'issuer': 'authelia.com',
                'period': 30,
                'skew': 1
            },
            
            # WebAuthn configuration for 2FA testing
            'webauthn': {
                'disable': False,
                'display_name': 'Authelia Fuzzing',
                'attestation_conveyance_preference': 'indirect',
                'user_verification': 'preferred',
                'timeout': '60s'
            },
            
            # New location for jwt_secret in 4.38+
            'identity_validation': {
                'reset_password': {
                    'jwt_secret': jwt_secret
                }
            },
            
            'authentication_backend': {
                'file': {
                    'path': '/config/users_database.yml',
                    'watch': False,
                    'search': {
                        'email': False,
                        'case_insensitive': False
                    },
                    'password': {
                        'algorithm': 'argon2',
                        'argon2': {
                            'variant': 'argon2id',
                            'iterations': 3,
                            'memory': 65536,
                            'parallelism': 4,
                            'key_length': 32,
                            'salt_length': 16
                        }
                    }
                }
            },
            
            'access_control': {
                'default_policy': default_policy,
                'rules': [
                    {
                        'domain': ['127.0.0.1'],
                        'policy': 'bypass',
                        'resources': ['^/api/health$', '^/api/oidc/.*', '^/api/state$', '^/api/configuration$']
                    },
                    {
                        'domain': ['127.0.0.1'],
                        'policy': default_policy
                    }
                ]
            },
            
            'session': {
                'name': 'authelia_session',
                'secret': session_secret,
                'same_site': 'lax',
                'expiration': '1h',
                'inactivity': '5m',
                'remember_me': '1M',
                'cookies': [
                    {
                        'domain': '127.0.0.1',
                        # Use HTTPS URLs now that TLS is enabled
                        'authelia_url': 'https://127.0.0.1:9091',
                        'default_redirection_url': 'https://127.0.0.1:7777'
                    }
                ]
            },
            
            'regulation': regulation_config,
            
            'storage': {
                'encryption_key': storage_key,
                'local': {
                    'path': '/data/db.sqlite3'
                }
            },
            
            'notifier': {
                'disable_startup_check': True,
                'filesystem': {
                    'filename': '/data/notification.txt'
                }
            },
            
            'identity_providers': {
                'oidc': {
                    'hmac_secret': hmac_secret,
                    'jwks': [
                        {
                            'key_id': 'fuzz-key-1',
                            'algorithm': 'RS256',
                            'use': 'sig',
                            'key': oidc_key_content
                        }
                    ],
                    'cors': {
                        'endpoints': ['authorization', 'token', 'revocation', 'introspection', 'userinfo'],
                        'allowed_origins_from_client_redirect_uris': True
                    },
                    'clients': [
                        {
                            'client_id': client_id,
                            'client_name': 'OAuth Fuzzing Client',
                            'client_secret': hashed_secret,
                            'public': False,
                            'authorization_policy': default_policy,
                            'require_pkce': authelia_cfg.get('require_pkce', False),
                            'pkce_challenge_method': 'S256',
                            # Fixed redirect_uri to match Authelia configuration
                            'redirect_uris': [
                                'https://127.0.0.1:7777/callback'
                            ],
                            'scopes': ['openid', 'profile', 'email', 'groups', 'offline_access'],
                            'grant_types': ['authorization_code', 'refresh_token'],
                            'response_types': ['code'],
                            'response_modes': ['form_post', 'query', 'fragment'],
                            'token_endpoint_auth_method': 'client_secret_post',
                            'userinfo_signed_response_alg': 'none',
                            'consent_mode': 'implicit'
                        }
                    ]
                }
            }
        }
    
    def _read_oidc_private_key(self) -> str:
        """Read the OIDC private key content from file"""
        key_path = os.path.join(self.config_dir, 'oidc_jwks.pem')
        
        # Generate key if it doesn't exist
        if not os.path.exists(key_path):
            self._generate_secrets()
        
        try:
            with open(key_path, 'r') as f:
                content = f.read().strip()
            
            # Validate it's a proper PEM
            if '-----BEGIN' not in content or '-----END' not in content:
                print(f"Warning: Invalid PEM format in {key_path}, regenerating...")
                os.remove(key_path)
                self._generate_rsa_key(key_path)
                with open(key_path, 'r') as f:
                    content = f.read().strip()
            
            return content
        except Exception as e:
            print(f"Error reading OIDC key: {e}")
            # Generate fresh key
            self._generate_rsa_key(key_path)
            with open(key_path, 'r') as f:
                return f.read().strip()
    
    def _generate_rsa_key(self, key_path: str) -> None:
        """Generate RSA private key using openssl"""
        try:
            subprocess.run([
                'openssl', 'genrsa', '-out', key_path, '4096'
            ], check=True, capture_output=True)
            os.chmod(key_path, 0o600)
            print(f"Generated RSA private key: {key_path}")
        except subprocess.CalledProcessError as e:
            print(f"openssl failed: {e}, trying Python fallback...")
            self._generate_rsa_key_fallback(key_path)
    
    def _generate_rsa_key_fallback(self, key_path: str) -> None:
        """Fallback RSA key generation using Python cryptography library"""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.backends import default_backend
            
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            with open(key_path, 'wb') as f:
                f.write(pem)
            os.chmod(key_path, 0o600)
            print(f"Generated OIDC private key (Python fallback): {key_path}")
        except ImportError:
            print("Warning: cryptography library not available, using dummy key")
            # Write a placeholder - Authelia will fail but at least we'll see logs
            with open(key_path, 'w') as f:
                f.write("# PLACEHOLDER - openssl and cryptography not available\n")
    
    def _build_users_database(self, oauth_cfg: Dict) -> Dict:
        """Build Authelia users database"""
        username = oauth_cfg.get('user', 'testuser')
        password = oauth_cfg.get('password', 'testpass')
        
        # Generate argon2id hash for password
        password_hash = self._generate_password_hash(password)
        
        return {
            'users': {
                username: {
                    'disabled': False,
                    'displayname': 'Test User',
                    'password': password_hash,
                    'email': f'{username}@example.com',
                    'groups': ['users', 'dev']
                }
            }
        }
    
    def _hash_client_secret(self, secret: str) -> str:
        """
        Generate a hashed client secret for Authelia.
        Authelia accepts plaintext secrets prefixed with $plaintext$ for testing.
        """
        return f'$plaintext${secret}'
    
    def _hash_client_secret_pbkdf2(self, secret: str) -> str:
        """
        Hash client secret using PBKDF2-SHA512 format that Authelia accepts.
        Format: $pbkdf2-sha512$i=iterations$salt$hash (PHC format)
        """
        import hashlib
        import base64
        try:
            import secrets as sec_module
            salt = sec_module.token_bytes(16)
        except ImportError:
            salt = b'0123456789abcdef'
        
        iterations = 310000
        dk = hashlib.pbkdf2_hmac('sha512', secret.encode(), salt, iterations, dklen=32)
        
        # Use standard base64 without padding (RawStdEncoding in Go)
        salt_b64 = base64.b64encode(salt).decode().rstrip('=')
        hash_b64 = base64.b64encode(dk).decode().rstrip('=')
        
        # PHC format requires 'i=' prefix for iterations parameter
        return f'$pbkdf2-sha512$i={iterations}${salt_b64}${hash_b64}'
    
    def _generate_password_hash(self, password: str) -> str:
        """
        Generate password hash for Authelia users database.
        Authelia requires argon2id format for user passwords.
        Format: $argon2id$v=19$m=65536,t=3,p=4$<salt_base64>$<hash_base64>
        """
        try:
            # Try using argon2-cffi library
            from argon2 import PasswordHasher
            from argon2.profiles import RFC_9106_LOW_MEMORY
            ph = PasswordHasher.from_parameters(RFC_9106_LOW_MEMORY)
            hash_result = ph.hash(password)
            print(f"  [Authelia] Password hash generated via argon2-cffi")
            return hash_result
        except ImportError:
            pass
        
        try:
            # Fallback: use hashlib with argon2 if available (Python 3.12+)
            import hashlib
            if hasattr(hashlib, 'argon2id'):
                import secrets as sec_module
                salt = sec_module.token_bytes(16)
                import base64
                
                hash_bytes = hashlib.argon2id(
                    password.encode(),
                    salt=salt,
                    time_cost=3,
                    memory_cost=65536,
                    parallelism=4,
                    hash_len=32
                )
                
                salt_b64 = base64.b64encode(salt).decode().rstrip('=')
                hash_b64 = base64.b64encode(hash_bytes).decode().rstrip('=')
                
                hash_result = f'$argon2id$v=19$m=65536,t=3,p=4${salt_b64}${hash_b64}'
                print(f"  [Authelia] Password hash generated via hashlib.argon2id")
                return hash_result
        except (ImportError, AttributeError):
            pass
        
        # Try generating hash using Docker (Authelia's own hasher)
        try:
            import subprocess
            # Try new CLI syntax first (Authelia 4.38+)
            commands = [
                ['docker', 'run', '--rm', 'authelia/authelia:latest',
                 'authelia', 'crypto', 'hash', 'generate', 'argon2',
                 '--password', password],
                # Fallback: old CLI syntax
                ['docker', 'run', '--rm', 'authelia/authelia:latest',
                 'authelia', 'hash-password', password],
            ]
            for cmd in commands:
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=60
                    )
                    if result.returncode == 0:
                        output = result.stdout.strip()
                        for line in output.split('\n'):
                            line = line.strip()
                            if line.startswith('Digest:'):
                                hash_result = line.split(':', 1)[1].strip()
                                print(f"  [Authelia] Password hash generated via Docker CLI")
                                return hash_result
                            elif line.startswith('Password hash:'):
                                hash_result = line.split(':', 1)[1].strip()
                                print(f"  [Authelia] Password hash generated via Docker CLI (legacy)")
                                return hash_result
                            elif line.startswith('$argon2'):
                                print(f"  [Authelia] Password hash generated via Docker CLI")
                                return line
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    continue
        except Exception:
            pass
        
        # Ultimate fallback - warn user
        print(f"  ⚠ WARNING: Could not generate password hash for '{password}'.")
        print(f"    Install argon2-cffi: pip install argon2-cffi")
        print(f"    Or ensure Docker Authelia image is available.")
        # Return a known hash - this may not work with all Authelia versions
        return '$argon2id$v=19$m=65536,t=3,p=4$BV1qMGHLBWXuOpDe+J3Akw$pRbL9YHxjAJPqvFtSPtnJQgPNhVt1RrEXCQkJJ8YLTk'
    
    def _generate_secrets(self) -> None:
        """Generate required secret files including OIDC private key and TLS certs"""
        secrets_dir = self.config_dir
        os.makedirs(secrets_dir, exist_ok=True)
        
        # Generate OIDC private key
        key_path = os.path.join(secrets_dir, 'oidc_jwks.pem')
        if os.path.exists(key_path):
            try:
                with open(key_path, 'r') as f:
                    content = f.read()
                if '-----BEGIN RSA PRIVATE KEY-----' not in content and '-----BEGIN PRIVATE KEY-----' not in content:
                    os.remove(key_path)
            except Exception:
                os.remove(key_path)
        
        if not os.path.exists(key_path):
            self._generate_rsa_key(key_path)
        else:
            print(f"Using existing OIDC private key: {key_path}")
        
        # Generate self-signed TLS certificate for HTTPS
        self._generate_tls_certificate()
    
    def _generate_tls_certificate(self) -> None:
        """Generate self-signed TLS certificate for Authelia server"""
        cert_path = os.path.join(self.config_dir, 'server.crt')
        key_path = os.path.join(self.config_dir, 'server.key')
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            print(f"Using existing TLS certificate: {cert_path}")
            return
        
        try:
            # Generate private key
            subprocess.run([
                'openssl', 'genrsa', '-out', key_path, '2048'
            ], check=True, capture_output=True)
            os.chmod(key_path, 0o600)
            
            # Generate self-signed certificate
            subprocess.run([
                'openssl', 'req', '-new', '-x509',
                '-key', key_path,
                '-out', cert_path,
                '-days', '365',
                '-subj', '/CN=127.0.0.1/O=Fuzzing/C=US',
                '-addext', 'subjectAltName=IP:127.0.0.1'
            ], check=True, capture_output=True)
            os.chmod(cert_path, 0o644)
            
            print(f"Generated TLS certificate: {cert_path}")
        except subprocess.CalledProcessError as e:
            print(f"Warning: Failed to generate TLS certificate: {e}")
            # Try older openssl syntax without -addext
            try:
                subprocess.run([
                    'openssl', 'req', '-new', '-x509',
                    '-key', key_path,
                    '-out', cert_path,
                    '-days', '365',
                    '-subj', '/CN=127.0.0.1/O=Fuzzing/C=US'
                ], check=True, capture_output=True)
                print(f"Generated TLS certificate (without SAN): {cert_path}")
            except subprocess.CalledProcessError as e2:
                print(f"Failed to generate TLS certificate: {e2}")
    
    def _write_yaml(self, path: str, data: Dict) -> None:
        """Write YAML configuration file"""
        try:
            import yaml
            with open(path, 'w') as f:
                yaml.dump(data, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        except ImportError:
            # Fallback: write as JSON (Authelia also accepts JSON)
            json_path = path.replace('.yml', '.json')
            with open(json_path, 'w') as f:
                json.dump(data, f, indent=2)
            print(f"Warning: PyYAML not installed, wrote JSON instead: {json_path}")
    
    def get_coverage_data(self) -> Optional[Dict]:
        """
        Get coverage data for Authelia.
        
        For Go coverage, collects data from GOCOVERDIR and parses
        using go tool covdata.
        
        Returns coverage data dict or None if coverage disabled.
        """
        if not self.coverage_enabled or not self.go_coverage:
            return None
        
        try:
            coverage = self.go_coverage.collect_coverage()
            if coverage:
                return coverage.to_dict()
        except Exception as e:
            print(f"[GoCoverage] Collection error: {e}")
        
        return None
    
    def dump_coverage(self, port: int = None) -> bool:
        """
        Trigger Go coverage dump.
        
        For Authelia, this collects coverage snapshots from the container.
        """
        if not self.coverage_enabled or not self.go_coverage:
            return False
        
        return self.go_coverage.dump_coverage()
    
    def generate_coverage_report(self, output_format: str = 'text') -> Optional[str]:
        """Generate Go coverage report"""
        if not self.coverage_enabled or not self.go_coverage:
            return None
        
        return self.go_coverage.generate_report(output_format)


def create_test_config_authelia() -> str:
    """Create a minimal test configuration for Authelia"""
    config = {
        "name": "oauth-authelia-fuzzer",
        "target_type": "authelia",
        "protocol": "OAUTH",
        "implementation": "Authelia",
        "output_dir": "out/oauth_authelia",
        "oauth": {
            "base_url": "http://127.0.0.1:9091",
            "realm": "authelia",
            "client_id": "fuzz-client",
            "client_secret": "fuzz-client-secret",
            "redirect_uri": "http://127.0.0.1:7777/callback",
            "user": "testuser",
            "password": "testpass",
            "scope": "openid profile email"
        },
        "authelia": {
            "container_name": "authelia-fuzz",
            "image": "authelia/authelia:latest",
            "config_dir": os.path.join(PROJECT_ROOT, 'targets_manager', 'authelia_service', 'config'),
            "work_dir": os.path.join(PROJECT_ROOT, 'targets_manager', 'authelia_service', 'work'),
            "http_port": 9091,
            "metrics_port": 9959,
            "log_level": "debug",
            "require_pkce": False,
            "coverage_enabled": False
        },
        "fuzzing": {
            "max_iterations": 1000,
            "timeout_seconds": 3600,
            "mutation_strategies": [
                "param_corruption",
                "header_injection",
                "url_manipulation"
            ]
        }
    }
    
    config_file = "authelia-fuzz-config.json"
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"Created Authelia configuration: {config_file}")
    return config_file


# Factory function for target manager creation
def create_oauth_manager(config: Dict) -> TargetManager:
    """
    Factory function to create appropriate OAuth manager based on target type.

    Args:
        config: Configuration dictionary with 'target_type' key

    Returns:
        Instance of KeycloakManager, AutheliaManager, SpringAuthzManager,
        CxfOAuthManager, or Wso2Manager.
    """
    target_type = config.get('target_type', 'keycloak').lower()

    if target_type in ('keycloak', 'java_based'):
        from targets_manager.keycloak_manager import KeycloakManager
        return KeycloakManager(config)
    elif target_type == 'authelia':
        return AutheliaManager(config)
    elif target_type == 'spring_authz':
        from targets_manager.spring_authz_manager import SpringAuthzManager
        return SpringAuthzManager(config)
    elif target_type == 'cxf_oauth':
        from targets_manager.cxf_oauth_manager import CxfOAuthManager
        return CxfOAuthManager(config)
    elif target_type == 'wso2':
        from targets_manager.wso2_manager import Wso2Manager
        return Wso2Manager(config)
    else:
        raise ValueError(
            f"Unknown target type: {target_type}. "
            f"Supported: keycloak, authelia, spring_authz, cxf_oauth, wso2"
        )


def main():
    """Main entry point for standalone Authelia management"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Authelia manager for OAuth fuzzing')
    parser.add_argument('--config', default='configs/oauth_authelia.json', help='Configuration file')
    parser.add_argument('--action', choices=['start', 'stop', 'restart', 'status', 'init-config'], 
                       default='start', help='Action to perform')
    
    args = parser.parse_args()
    
    if args.action == 'init-config':
        create_test_config_authelia()
        return
    
    # Load configuration
    if os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    else:
        print(f"Configuration file not found: {args.config}")
        print("Creating default configuration...")
        config_file = create_test_config_authelia()
        with open(config_file, 'r') as f:
            config = json.load(f)
    
    # Create Authelia manager
    am = AutheliaManager(config)
    
    if args.action == 'start':
        if am.start_authelia():
            print("Authelia is ready for fuzzing!")
        else:
            print("Failed to start Authelia")
            sys.exit(1)
    
    elif args.action == 'stop':
        am.stop_authelia()
    
    elif args.action == 'restart':
        am.stop_authelia()
        time.sleep(3)
        am.start_authelia()
    
    elif args.action == 'status':
        if am.is_healthy():
            print("Authelia is running and healthy")
        else:
            print("Authelia is not accessible")


if __name__ == "__main__":
    main()