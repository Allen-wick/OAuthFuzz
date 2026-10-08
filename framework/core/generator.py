#!/usr/bin/env python3
"""OAuth request generation and coverage-integrated fuzzing."""

import os
import time
import json
import random
import requests
import urllib.parse
import hashlib
import threading
from typing import Dict, List, Optional
from http.server import BaseHTTPRequestHandler, HTTPServer

from core.coverage import CoverageData, JaCoCoManager  

class OAuthRequestGenerator:
    """
    OAuth request generator with mutation capabilities
    Supports multiple OAuth providers: Keycloak, Authelia
    """
    
    def __init__(self, config: Dict, target_type: str = 'keycloak'):
        # Accept either full config or oauth sub-config
        self._full_config = config
        self.base_config = config.get('oauth', config)
        self.target_type = target_type.lower()
        self.session = requests.Session()
        self.session.verify = False  # For self-signed certs
        
        # Target-aware endpoint configuration
        base_url = self.base_config.get('base_url', 'http://127.0.0.1:8080')
        realm = self.base_config.get('realm', 'fuzz')
        
        if self.target_type == 'authelia':
            # Authelia endpoints (no realm)
            self.endpoints = {
                'authorize': f"{base_url}/api/oidc/authorization",
                'token': f"{base_url}/api/oidc/token",
                'userinfo': f"{base_url}/api/oidc/userinfo",
                'introspect': f"{base_url}/api/oidc/introspection",
                'revoke': f"{base_url}/api/oidc/revocation",
                'firstfactor': f"{base_url}/api/firstfactor",
                'secondfactor_totp': f"{base_url}/api/secondfactor/totp",
                'logout': f"{base_url}/api/logout",
                'consent': f"{base_url}/api/oidc/consent",
                'state': f"{base_url}/api/state",
                'configuration': f"{base_url}/api/configuration",
            }
        elif self.target_type == 'authentik':
            app_slug = self._full_config.get('authentik', {}).get('app_slug', 'fuzz-app')
            discovery_url = f"{base_url}/application/o/{app_slug}/.well-known/openid-configuration"
            discovered = {}
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                r = requests.get(discovery_url, timeout=5,
                                 headers={'Accept': 'application/json'},
                                 verify=False)
                if r.status_code == 200:
                    discovered = r.json()
                    print(f"[OIDC Discovery] ✓ {discovery_url}")
            except Exception as e:
                print(f"[OIDC Discovery] fallback for authentik (reason: {e})")

            self.endpoints = {
                'authorize':    discovered.get('authorization_endpoint',   f"{base_url}/application/o/authorize/"),
                'token':        discovered.get('token_endpoint',           f"{base_url}/application/o/token/"),
                'userinfo':     discovered.get('userinfo_endpoint',        f"{base_url}/application/o/userinfo/"),
                'introspect':   discovered.get('introspection_endpoint',   f"{base_url}/application/o/introspect/"),
                'revoke':       discovered.get('revocation_endpoint',      f"{base_url}/application/o/revoke/"),
                'jwks':         discovered.get('jwks_uri',                 f"{base_url}/application/o/{app_slug}/jwks/"),
                'openid_config': discovery_url,
            }
            self.server_meta = discovered
        elif self.target_type in ('spring_authz', 'cxf_oauth', 'wso2'):
            # Generic OIDC-compliant targets.  Use RFC 8414 discovery when
            # it is reachable — this keeps the fuzzer correct even if the
            # deployment moves endpoints.  Otherwise fall back to the
            # per-target conventional paths (same table as
            # protocol/<target>.py::_configure_endpoints fallback).
            issuer_paths = {
                'spring_authz': '',
                'cxf_oauth':    '/services/oidc',
                'wso2':         '/oauth2/oidcdiscovery',
            }
            fallback_paths = {
                'spring_authz': {
                    'authorize':    '/oauth2/authorize',
                    'token':        '/oauth2/token',
                    'userinfo':     '/userinfo',
                    'introspect':   '/oauth2/introspect',
                    'revoke':       '/oauth2/revoke',
                    'jwks':         '/oauth2/jwks',
                    'openid_config':'/.well-known/openid-configuration',
                },
                'cxf_oauth': {
                    'authorize':    '/services/oauth2/authorize',
                    'token':        '/services/oauth2/token',
                    'userinfo':     '/services/oidc/userinfo',
                    'introspect':   '/services/oauth2/introspect',
                    'revoke':       '/services/oauth2/revoke',
                    'jwks':         '/services/oidc/jwk',
                    'openid_config':'/services/oidc/.well-known/openid-configuration',
                },
                'wso2': {
                    'authorize':    '/oauth2/authorize',
                    'token':        '/oauth2/token',
                    'userinfo':     '/oauth2/userinfo',
                    'introspect':   '/oauth2/introspect',
                    'revoke':       '/oauth2/revoke',
                    'jwks':         '/oauth2/jwks',
                    'openid_config':'/oauth2/oidcdiscovery/.well-known/openid-configuration',
                },
            }
            fb = fallback_paths[self.target_type]
            issuer_path = issuer_paths[self.target_type]
            discovery_url = f"{base_url}{issuer_path}/.well-known/openid-configuration"

            # Try discovery first; don't fail init if it's not reachable yet
            discovered = {}
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                r = requests.get(discovery_url, timeout=5,
                                 headers={'Accept': 'application/json'},
                                 verify=False)
                if r.status_code == 200:
                    discovered = r.json()
                    print(f"[OIDC Discovery] ✓ {discovery_url}")
            except Exception as e:
                print(f"[OIDC Discovery] fallback for {self.target_type} "
                      f"(reason: {e})")

            self.endpoints = {
                'authorize':    discovered.get('authorization_endpoint',   f"{base_url}{fb['authorize']}"),
                'token':        discovered.get('token_endpoint',           f"{base_url}{fb['token']}"),
                'userinfo':     discovered.get('userinfo_endpoint',        f"{base_url}{fb['userinfo']}"),
                'introspect':   discovered.get('introspection_endpoint',   f"{base_url}{fb['introspect']}"),
                'revoke':       discovered.get('revocation_endpoint',      f"{base_url}{fb['revoke']}"),
                'jwks':         discovered.get('jwks_uri',                 f"{base_url}{fb['jwks']}"),
                'openid_config': discovery_url,
            }
            # Keep discovery metadata for the mutator (supported scopes/rt)
            self.server_meta = discovered
        elif self.target_type == 'simplelogin':
            self.endpoints = {
                'authorize': f"{base_url}/oauth2/authorize",
                'token':     f"{base_url}/oauth2/token",
                'userinfo':  f"{base_url}/oauth2/userinfo",
                'login':     f"{base_url}/auth/login",
                'register':  f"{base_url}/api/auth/register",
                'openid_config': f"{base_url}/.well-known/openid-configuration",
                'jwks':      f"{base_url}/jwks",
                'introspect': f"{base_url}/oauth2/introspect",
                'revoke':     f"{base_url}/oauth2/revoke",
            }
        elif self.target_type == 'nodeoidc':
            # base_url already includes /oidc prefix
            self.endpoints = {
                'authorize': f"{base_url}/auth",
                'token':     f"{base_url}/token",
                'userinfo':  f"{base_url}/me",
                'introspect': f"{base_url}/token/introspection",
                'revoke':     f"{base_url}/token/revocation",
                'openid_config': f"{base_url}/.well-known/openid-configuration",
                'jwks':      f"{base_url}/jwks",
                'device':    f"{base_url}/device/auth",
            }
        elif self.target_type == 'logto':
            # Logto uses /oidc/* prefix for all OIDC endpoints
            self.endpoints = {
                'authorize': f"{base_url}/oidc/auth",
                'token':     f"{base_url}/oidc/token",
                'userinfo':  f"{base_url}/oidc/me",
                'introspect': f"{base_url}/oidc/token/introspection",
                'revoke':     f"{base_url}/oidc/token/revocation",
                'openid_config': f"{base_url}/oidc/.well-known/openid-configuration",
                'jwks':      f"{base_url}/oidc/jwks",
            }
        else:
            # Keycloak endpoints (with realm)
            self.endpoints = {
                'authorize': f"{base_url}/realms/{realm}/protocol/openid-connect/auth",
                'token': f"{base_url}/realms/{realm}/protocol/openid-connect/token",
                'userinfo': f"{base_url}/realms/{realm}/protocol/openid-connect/userinfo",
                'introspect': f"{base_url}/realms/{realm}/protocol/openid-connect/token/introspect",
                'revoke': f"{base_url}/realms/{realm}/protocol/openid-connect/logout",
                'openid_config': f"{base_url}/realms/{realm}/.well-known/openid-configuration",
                'jwks': f"{base_url}/realms/{realm}/protocol/openid-connect/certs",
            }
        
        # State management
        self.state = None
        self.nonce = None
        self.code_verifier = None
        self.code_challenge = None
        
        # Server metadata (lazy loaded)
        self.server_meta = {}
        
        # Mutation tracking
        self.mutation_count = 0
        
        self._init_pkce()
    
    def _init_pkce(self):
        """Initialize PKCE parameters"""
        import secrets
        import hashlib
        import base64
        
        self.state = secrets.token_urlsafe(32)
        self.nonce = secrets.token_urlsafe(32)
        self.code_verifier = secrets.token_urlsafe(32)
        digest = hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        self.code_challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')

    def _load_server_metadata(self):
        """Load OpenID Connect discovery metadata"""
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            r = requests.get(self.endpoints['openid_config'], timeout=8, verify=False)
            if r.status_code == 200:
                self.server_meta = r.json()
        except Exception:
            self.server_meta = {}

    def generate_openid_config_request(self) -> Dict:
        return {
            'method': 'GET',
            'url': self.endpoints['openid_config'],
            'headers': {'User-Agent': 'OAuthFuzzer/1.0', 'Accept': 'application/json'}
        }

    def generate_jwks_request(self) -> Dict:
        return {
            'method': 'GET',
            'url': self.endpoints['jwks'],
            'headers': {'User-Agent': 'OAuthFuzzer/1.0', 'Accept': 'application/json'}
        }

    def generate_introspect_request(self, access_token: str) -> Dict:
        data = {
            'client_id': self.base_config.get('client_id', 'test-client'),
            'client_secret': self.base_config.get('client_secret', 'test-secret'),
            'token': access_token
        }
        return {
            'method': 'POST',
            'url': self.endpoints['introspect'],
            'data': data,
            'headers': {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'OAuthFuzzer/1.0'}
        }

    def generate_password_grant_request(self, mutations: Dict = None) -> Dict:
        """Generate OAuth password grant request (direct access grants)"""
        data = {
            'grant_type': 'password',
            'username': self.base_config.get('user', 'testuser'),
            'password': self.base_config.get('password', 'testpass'),
            'client_id': self.base_config.get('client_id', 'test-client'),
            'client_secret': self.base_config.get('client_secret', 'test-secret'),
            'scope': self.base_config.get('scope', 'openid profile email'),
        }
        if mutations:
            data.update(mutations)
        return {
            'method': 'POST',
            'url': self.endpoints['token'],
            'data': data,
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'OAuthFuzzer/1.0'
            }
        }
        
    def generate_authorize_request(self, mutations: Dict = None) -> Dict:
        """Generate OAuth authorize request with mutations"""
        # Use raw redirect_uri - don't pre-encode it
        redirect_uri = self.base_config.get('redirect_uri', 'http://127.0.0.1:7777/callback')

        params = {
            'response_type': 'code',
            'client_id': self.base_config.get('client_id', 'test-client'),
            'redirect_uri': redirect_uri,
            'scope': self.base_config.get('scope', 'openid profile email'),
            'state': self._generate_state(),
            'nonce': self._generate_nonce()
        }

        # Add PKCE for targets that require it (Logto, etc.)
        if self.target_type in ('logto',):
            params['code_challenge'] = self.code_challenge
            params['code_challenge_method'] = 'S256'

        # Apply mutations
        if mutations:
            params.update(mutations)
        
        return {
            'method': 'GET',
            'url': self.endpoints['authorize'],
            'params': params,
            'headers': {
                'User-Agent': 'OAuthFuzzer/1.0',
                'Accept': 'text/html,application/xhtml+xml'
            }
        }
    
    def generate_token_request(self, auth_code: str, mutations: Dict = None) -> Dict:
        """Generate OAuth token request with mutations"""
        redirect_uri = self.base_config.get('redirect_uri', 'http://127.0.0.1:7777/callback')

        data = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': redirect_uri,
            'client_id': self.base_config.get('client_id', 'test-client'),
            'client_secret': self.base_config.get('client_secret', 'test-secret')
        }

        # Add PKCE code_verifier for targets that require it (Logto, etc.)
        if self.target_type in ('logto',) and self.code_verifier:
            data['code_verifier'] = self.code_verifier

        # Apply mutations
        if mutations:
            data.update(mutations)
        
        return {
            'method': 'POST',
            'url': self.endpoints['token'],
            'data': data,
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'OAuthFuzzer/1.0'
            }
        }
    
    def generate_userinfo_request(self, access_token: str, mutations: Dict = None) -> Dict:
        """Generate OAuth userinfo request with mutations"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'User-Agent': 'OAuthFuzzer/1.0',
            'Accept': 'application/json'
        }
        
        # Apply mutations
        if mutations:
            headers.update(mutations.get('headers', {}))
        
        return {
            'method': 'GET',
            'url': self.endpoints['userinfo'],
            'headers': headers
        }
    
    def _generate_state(self) -> str:
        """Generate random state parameter"""
        import secrets
        return secrets.token_urlsafe(32)
    
    def _generate_nonce(self) -> str:
        """Generate random nonce parameter"""
        import secrets
        return secrets.token_urlsafe(32)
    
    def mutate_request(self, request: Dict) -> Dict:
        """Apply mutations to request"""
        self.mutation_count += 1
        mutated = request.copy()
        
        strategies = [
            ("smart_params", 0.6),
            ("headers", 0.2),
            ("method", 0.1),
            ("url", 0.1)
        ]
        import random
        r = random.random()
        acc = 0.0
        choice = "smart_params"
        for name, prob in strategies:
            acc += prob
            if r <= acc:
                choice = name
                break

        if choice == "smart_params":
            self._mutate_oauth_params_smart(mutated)
        elif choice == "headers":
            self._mutate_headers(mutated)
        elif choice == "method":
            self._mutate_method(mutated)
        else:
            # 降低破坏性：仅对 authorize 的 URL 尝试轻微扰动，避免路径投毒
            if mutated.get('method') == 'GET' and 'auth' in mutated.get('url', ''):
                self._mutate_url(mutated)
        
        return mutated
    
    def _mutate_params(self, request: Dict):
        """Mutate request parameters"""
        if 'params' in request:
            params = request['params']
            # Corrupt parameter values
            for key in params:
                if isinstance(params[key], str):
                    params[key] = self._corrupt_string(params[key])
        
        if 'data' in request:
            data = request['data']
            for key in data:
                if isinstance(data[key], str):
                    data[key] = self._corrupt_string(data[key])
    
    def _mutate_headers(self, request: Dict):
        """Mutate request headers (mild)"""
        if 'headers' in request:
            headers = request['headers']
            headers['X-Requested-With'] = random.choice(['XMLHttpRequest', 'fetch'])
            headers['X-Forwarded-Proto'] = random.choice(['http', 'https'])
    
    def _mutate_url(self, request: Dict):
        """Mutate request URL (mild)"""
        if 'url' in request:
            url = request['url']
            if '?' in url:
                request['url'] = url + '&cb=' + self._generate_state()
            else:
                request['url'] = url + '?cb=' + self._generate_state()
    
    def _mutate_method(self, request: Dict):
        """Mutate HTTP method"""
        if 'method' in request:
            methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
            request['method'] = random.choice(methods)
    
    def _corrupt_string(self, s: str) -> str:
        """Corrupt string with various techniques"""
        import random
        
        corruption_methods = [
            lambda x: x + '\x00',  # Null byte injection
            lambda x: x.replace('=', '=='),  # Double encoding
            lambda x: x + '; DROP TABLE users; --',  # SQL injection
            lambda x: x + '<script>alert(1)</script>',  # XSS
            lambda x: x[::-1],  # Reverse string
            lambda x: x.upper(),  # Case change
            lambda x: x + 'A' * 1000,  # Buffer overflow attempt
        ]
        
        return random.choice(corruption_methods)(s)

    def _mutate_oauth_params_smart(self, request: Dict):
        """Gently mutate known OAuth parameters to increase valid path coverage"""
        import random, urllib.parse, time, base64, json
        targets = set(["response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
                       "grant_type", "code", "username", "password"])
        supported_rt = self.server_meta.get('response_types_supported', ['code'])
        supported_scopes = (self.server_meta.get('scopes_supported') or ['openid','profile','email'])
        # params for GET, data for POST
        if 'params' in request and isinstance(request['params'], dict):
            for k in list(request['params'].keys()):
                if k in targets and isinstance(request['params'][k], str):
                    v = request['params'][k]
                    if k == 'response_type':
                        request['params'][k] = random.choice([rt for rt in supported_rt if rt in ['code','id_token','code id_token']] or ['code'])
                    elif k == 'scope':
                        add = random.choice(['address', 'phone', 'offline_access'])
                        if add in supported_scopes or add == 'offline_access':
                            request['params'][k] = v + ' ' + add
                    elif k == 'redirect_uri':
                        base = v.split('?')[0]
                        if random.random() < 0.5:
                            request['params'][k] = base + '?cb=' + self._generate_state()
                        else:
                            # 双重编码混淆
                            enc = urllib.parse.quote(base, safe='')
                            request['params'][k] = urllib.parse.quote(enc, safe='')
                    elif k in ('state', 'nonce'):
                        request['params'][k] = self._generate_state()
                    elif k == 'client_id':
                        request['params'][k] = v[:min(len(v), 10)] + '_fuzz'
        if 'data' in request and isinstance(request['data'], dict):
            for k in list(request['data'].keys()):
                if k in targets and isinstance(request['data'][k], str):
                    v = request['data'][k]
                    if k == 'grant_type':
                        gt = random.choice(['authorization_code', 'password', 'client_credentials', 'refresh_token'])
                        request['data'][k] = gt
                    elif k == 'scope':
                        add = random.choice(['profile', 'email', 'address', 'offline_access'])
                        request['data'][k] = v + ' ' + add
                    elif k in ('username', 'password'):
                        request['data'][k] = v + random.choice(['1', '_', '.'])
                    elif k == 'client_id':
                        request['data'][k] = v[:min(len(v), 10)] + '_f'
        # JWT 令牌专项变异（用于 userinfo/introspect）
        if request.get('method') == 'GET' and 'userinfo' in request.get('url',''):
            def b64(x):
                return base64.urlsafe_b64encode(json.dumps(x).encode()).decode().rstrip("=")
            jwt = random.choice([
                f"{b64({'alg':'none'})}.{b64({'sub':'fuzz','exp':int(time.time())+60})}.",
                f"{b64({'alg':'RS256','kid':'invalid'})}.{b64({'sub':'fuzz','exp':int(time.time())+60})}.{b64('sig')}",
                f"{b64({'alg':'RS256'})}.{b64({'sub':'fuzz','exp':int(time.time())-1})}.{b64('sig')}"
            ])
            request.setdefault('headers', {})
            request['headers']['Authorization'] = f"Bearer {jwt}"

class OAuthFuzzerWithCoverage:
    """
    Complete OAuth fuzzer with real Java coverage integration
    """
    
    def __init__(self, config: Dict, jacoco_manager: Optional[JaCoCoManager] = None):
        self.config = config
        
        # Detect target type
        self.target_type = config.get('target_type', 'keycloak').lower()
        
        # All JVM-based targets share the JaCoCo pipeline.  The previous
        # whitelist only included Keycloak, silently disabling coverage for
        # spring_authz / cxf_oauth / wso2 even when
        # run_oauth_fuzzing.py had already built a live JaCoCoManager with
        # classpaths populated.  Treat the passed-in manager as the source
        # of truth: if the caller handed one over, use it; otherwise only
        # skip for known non-JVM targets (authelia).
        _NON_JVM_TARGETS = ('authelia', 'authentik', 'simplelogin', 'nodeoidc', 'logto')
        if self.target_type in _NON_JVM_TARGETS:
            self.jacoco = None
            print(f"[Coverage] JaCoCo disabled for {self.target_type} (non-Java target)")
        else:
            self.jacoco = jacoco_manager or JaCoCoManager()
            if self.jacoco:
                print(f"[Coverage] JaCoCo enabled for {self.target_type} "
                      f"(classpaths={len(getattr(self.jacoco, 'classpaths', []) or [])})")
        
        self.request_generator = OAuthRequestGenerator(config, target_type=self.target_type)
        
        # 覆盖类路径兜底（从配置读取）- only for Java targets
        if self.jacoco:
            try:
                cps = config.get('jacoco', {}).get('classpaths', [])
                if cps:
                    self.jacoco.set_classpaths(cps)
            except Exception:
                pass
        
        # Coverage tracking
        self.baseline_coverage = CoverageData()
        self.current_coverage = CoverageData()
        self.coverage_history: List[CoverageData] = []
        self.interesting_cases: List[Dict] = []

        # === Streamlined sequence/result log ===
        # Individual interesting_case_NNNNNN.json files were discontinued
        # because (a) with 400/501 responses from 404 misrouting every
        # iteration was "interesting", producing thousands of near-identical
        # files, and (b) they carry no information the JSONL log doesn't.
        # Config flag fuzzing.save_interesting_cases=true can re-enable the
        # per-file dumps for debugging if ever needed.
        self._save_interesting_cases: bool = bool(
            config.get('fuzzing', {}).get('save_interesting_cases', False)
        )
        output_dir = config.get('output_dir', 'out/oauth_fuzz')
        try:
            os.makedirs(output_dir, exist_ok=True)
        except Exception:
            pass
        self._sequence_log_path = os.path.join(output_dir, 'sequences.jsonl')
        try:
            # Line-buffered append stream; flushed on every record so a
            # crashed run still has a complete trace up to the last iteration.
            self._sequence_log_fh = open(self._sequence_log_path, 'a', buffering=1)
        except Exception as e:
            print(f"[SeqLog] Disabled: cannot open {self._sequence_log_path}: {e}")
            self._sequence_log_fh = None

        # Dump/report throttling — heavy JaCoCo work only every N iterations.
        self._dump_every_n: int = int(
            config.get('jacoco', {}).get('dump_every_n', 25) or 25
        )
        self._last_coverage_pct: float = 0.0

        # State tracking for state-based coverage (used by Authelia/Go targets)
        self.seen_state_signatures: set = set()
        
        # Go coverage manager (injected from run_oauth_fuzzing.py for Authelia)
        self.go_coverage = None

        # Session management
        self.session = requests.Session()
        
        # Disable SSL verification for self-signed certificates
        oauth_cfg = config.get('oauth', {})
        if not oauth_cfg.get('verify_ssl', True):
            self.session.verify = False
            # Suppress SSL warnings
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            print("[SSL] Certificate verification disabled for self-signed certs")
        
        self.execution_count = 0
        self.mutation_count = 0
        self.last_access_token: Optional[str] = None
        self.last_auth_code: Optional[str] = None

        # 启动本地回调服务器
        self._setup_callback_server()
        
        # Initialize baseline coverage
        self._establish_baseline()
    
    def _setup_callback_server(self):
        """Start a local HTTP callback server to capture authorization code"""
        ru = urllib.parse.urlparse(self.config.get('oauth', {}).get('redirect_uri', 'http://127.0.0.1:7777/callback'))
        host = ru.hostname or '127.0.0.1'
        port = ru.port or 7777
        path = ru.path or '/callback'

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == self.server.expected_path:
                    qs = urllib.parse.parse_qs(parsed.query)
                    code = qs.get('code', [None])[0]
                    state = qs.get('state', [None])[0]
                    self.server.last_code = code
                    self.server.last_state = state
                    self.server.event.set()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(b'OK')
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, fmt, *args):
                return

        self._cb_server = HTTPServer((host, port), CallbackHandler)
        self._cb_server.expected_path = path
        self._cb_server.event = threading.Event()
        self._cb_server.last_code = None
        self._cb_thread = threading.Thread(target=self._cb_server.serve_forever, daemon=True)
        self._cb_thread.start()
        # print(f"Callback server started on {host}:{port}{path}")

    def _wait_for_code(self, timeout: int = 20) -> Optional[str]:
        """Wait for code captured by callback server"""
        if self._cb_server.event.wait(timeout):
            return self._cb_server.last_code
        return None

    def stop(self):
        """Stop callback server"""
        try:
            if hasattr(self, "_cb_server"):
                self._cb_server.shutdown()
                self._cb_server.server_close()
        except Exception:
            pass

    def _establish_baseline(self):
        """Establish baseline coverage with normal OAuth flow"""
        print("Establishing baseline coverage...")
        
        target_type = self.config.get('target_type', 'keycloak').lower()
        
        # Try authorization code flow first
        try:
            self._perform_authorization_code_flow()
        except Exception as e:
            print(f"Auth code flow failed in baseline: {e}")
            
            # Password grant fallback - only for Keycloak (Authelia/Authentik/SimpleLogin don't support it)
            if target_type not in ('authelia', 'authentik', 'simplelogin', 'nodeoidc', 'logto'):
                try:
                    self._perform_password_grant_flow()
                except Exception as e2:
                    print(f"Password grant flow failed in baseline: {e2}")
            else:
                print(f"Password grant not supported by {target_type}, skipping...")

        # 主动 dump 覆盖数据 (only for Java targets)
        if self.jacoco:
            jp = self.config.get('jacoco', {}).get('agent_port', 6300)
            self.jacoco.dump_coverage(port=jp)

        # 生成覆盖
        self.baseline_coverage = self._get_current_coverage()
        print(f"Baseline coverage: {self.baseline_coverage.coverage_percentage:.2f}%")

    def _perform_password_grant_flow(self):
        """Perform OAuth password grant to establish baseline session"""
        req = self.request_generator.generate_password_grant_request()
        r = self.session.post(req['url'], data=req['data'], headers=req['headers'], timeout=15)
        if r.status_code != 200:
            raise RuntimeError(f"Password grant failed: {r.status_code} {r.text}")
        tj = {}
        try:
            tj = r.json()
        except Exception:
            pass
        self.last_access_token = tj.get('access_token')
        if self.last_access_token:
            ui_req = self.request_generator.generate_userinfo_request(self.last_access_token)
            _ = self._execute_request(ui_req)

    def _perform_authorization_code_flow(self):
        """Perform full OAuth authorization code flow (supports Keycloak and Authelia)"""
        oauth = self.config.get('oauth', {})
        base_url = oauth.get('base_url')
        user = oauth.get('user')
        password = oauth.get('password')
        target_type = self.config.get('target_type', 'keycloak').lower()

        # Generate authorize request
        auth_req = self.request_generator.generate_authorize_request()
        # For Logto, use allow_redirects=False to capture the session cookie without
        # following the redirect chain to the callback URL (which doesn't exist).
        use_redirects = target_type not in ('logto',)
        r1 = self.session.get(auth_req['url'], params=auth_req['params'], headers=auth_req['headers'], timeout=15, allow_redirects=use_redirects)

        full_auth_url = r1.url if hasattr(r1, 'url') else auth_req['url']
        
        if target_type == 'authelia':
            return self._perform_authelia_auth_flow(oauth, base_url, user, password, full_auth_url, auth_req)
        elif target_type == 'authentik':
            return self._perform_authentik_auth_flow(oauth, base_url, user, password, r1, auth_req)
        elif target_type == 'simplelogin':
            return self._perform_simplelogin_auth_flow(oauth, base_url, user, password, r1, auth_req)
        elif target_type == 'nodeoidc':
            return self._perform_nodeoidc_auth_flow(oauth, base_url, user, password, r1, auth_req)
        elif target_type == 'logto':
            return self._perform_logto_auth_flow(oauth, base_url, user, password, r1, auth_req)
        else:
            return self._perform_keycloak_auth_flow(oauth, base_url, user, password, r1.text, auth_req)
    
    def _perform_simplelogin_auth_flow(self, oauth: Dict, base_url: str, user: str, password: str,
                                        auth_resp, auth_req: Dict):
        """Perform SimpleLogin auth: authorize page → extract login link → login → follow redirects."""
        import re

        # Step 1: The authorize page (auth_resp) shows login/register links when unauthenticated.
        # Extract the login link which carries the ?next= parameter back to authorize.
        login_link_match = re.search(r'href="(/auth/login\?[^"]+)"', auth_resp.text)
        if login_link_match:
            login_url = f"{base_url}{login_link_match.group(1).replace('&amp;', '&')}"
        else:
            login_url = f"{base_url}/auth/login?next={auth_req['url']}"

        # Step 2: GET login page for CSRF token
        r_login_page = self.session.get(login_url, timeout=15, allow_redirects=True)
        csrf_token = None
        csrf_match = re.search(
            r'name="csrf_token"[^>]*value="([^"]+)"',
            r_login_page.text, re.IGNORECASE,
        )
        if csrf_match:
            csrf_token = csrf_match.group(1)

        # Step 3: POST login form
        login_data = {'email': user, 'password': password}
        if csrf_token:
            login_data['csrf_token'] = csrf_token

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': base_url,
            'Referer': login_url,
        }
        r2 = self.session.post(login_url, data=login_data, headers=headers,
                               timeout=15, allow_redirects=False)

        # Step 4: Follow redirect chain to extract auth code.
        # Login redirects back to /oauth2/authorize, which (with pre-approved client)
        # redirects to the callback URL with the auth code.
        target_url = r2.headers.get('Location', '')
        code = None
        for _ in range(10):
            if not target_url:
                break
            if not target_url.startswith('http'):
                target_url = f"{base_url}{target_url}"
            if 'code=' in target_url:
                m = re.search(r'code=([a-zA-Z0-9\-._~]+)', target_url)
                if m:
                    code = m.group(1)
                break
            resp = self.session.get(target_url, allow_redirects=False, timeout=15)
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            target_url = resp.headers.get('Location', '')

        if not code:
            raise RuntimeError("SimpleLogin: no auth code obtained from authorization flow")

        self.last_auth_code = code

        # Step 5: Exchange code for token
        token_req = self.request_generator.generate_token_request(code)
        r4 = self.session.post(token_req['url'], data=token_req['data'],
                               headers=token_req['headers'], timeout=15)
        if r4.status_code != 200:
            raise RuntimeError(f"SimpleLogin: token exchange failed: {r4.status_code} {r4.text[:200]}")

        token_data = r4.json()
        self.last_access_token = token_data.get('access_token')
        self.auth_result = token_data

        if self.last_access_token:
            ui_req = self.request_generator.generate_userinfo_request(self.last_access_token)
            _ = self._execute_request(ui_req)

        return token_data

    def _perform_nodeoidc_auth_flow(self, oauth: Dict, base_url: str, user: str, password: str,
                                     auth_resp, auth_req: Dict):
        """Perform node-oidc-provider auth: authorize → auto-approve interaction → follow redirects → code.

        node-oidc-provider auto-approves login/consent via server.js, so the flow
        is simpler than other targets. The authorize request redirects to the
        interaction page, which auto-completes and redirects to the callback with
        the auth code.
        """
        import urllib.parse

        # Re-issue authorize request with allow_redirects=False to capture Location header
        r1 = self.session.get(auth_req['url'], params=auth_req.get('params'),
                              headers=auth_req.get('headers', {}),
                              timeout=15, allow_redirects=False)
        target_url = r1.headers.get('Location', '')
        if not target_url:
            raise RuntimeError("node-oidc-provider: authorize did not redirect")

        # Follow redirect chain to get the auth code.
        code = None
        plain_base = base_url.replace('/oidc', '') if '/oidc' in base_url else base_url
        for _ in range(10):
            if not target_url.startswith('http'):
                target_url = f"{plain_base}{target_url}"

            resp = self.session.get(target_url, allow_redirects=False, timeout=15)
            location = resp.headers.get('Location', '')

            if location and 'code=' in location:
                q = urllib.parse.urlparse(location).query
                params = urllib.parse.parse_qs(q)
                code = params.get('code', [None])[0]
                break

            if not location or resp.status_code not in (301, 302, 303, 307, 308):
                break
            target_url = location

        if not code:
            raise RuntimeError("node-oidc-provider: no auth code obtained from authorization flow")

        self.last_auth_code = code

        # Exchange code for token
        token_req = self.request_generator.generate_token_request(code)
        r4 = self.session.post(token_req['url'], data=token_req['data'],
                               headers=token_req['headers'], timeout=15)
        if r4.status_code != 200:
            raise RuntimeError(f"node-oidc-provider: token exchange failed: {r4.status_code} {r4.text[:200]}")

        token_data = r4.json()
        self.last_access_token = token_data.get('access_token')
        self.auth_result = token_data

        if self.last_access_token:
            ui_req = self.request_generator.generate_userinfo_request(self.last_access_token)
            _ = self._execute_request(ui_req)

        return token_data

    def _perform_logto_auth_flow(self, oauth: Dict, base_url: str, user: str, password: str,
                                  auth_resp, auth_req: Dict):
        """Perform Logto auth flow using Interaction API.

        Logto uses a React SPA frontend that communicates with the Interaction API:
          0. GET /oidc/auth?... → establishes session, redirects to /sign-in
          1. PUT  /api/experience → {"interactionEvent":"SignIn"}
          2. POST /api/experience/verification/password → {identifier, password}
          3. POST /api/experience/identification → {verificationId}
          4. POST /api/experience/submit → {} → {redirectTo}
          5. Follow redirects → handle consent → extract auth code
        """
        import urllib.parse

        # The authorize request used allow_redirects=False, so we need to manually
        # follow the redirect to /sign-in to establish the session cookies.
        sign_in_url = auth_resp.headers.get('Location', '')
        if sign_in_url:
            if not sign_in_url.startswith('http'):
                sign_in_url = base_url + (sign_in_url if sign_in_url.startswith('/') else '/' + sign_in_url)
            self.session.get(sign_in_url, timeout=15, allow_redirects=True)

        # Step 1: Initiate SignIn interaction
        experience_url = f"{base_url}/api/experience"
        r_exp = self.session.put(
            experience_url,
            json={"interactionEvent": "SignIn"},
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            timeout=15, allow_redirects=False)
        if r_exp.status_code not in (200, 204):
            raise RuntimeError(f"Logto: experience PUT failed: {r_exp.status_code} {r_exp.text[:200]}")

        # Step 2: Password verification
        verify_url = f"{base_url}/api/experience/verification/password"
        r_verify = self.session.post(
            verify_url,
            json={
                "identifier": {"type": "username", "value": user},
                "password": password,
            },
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            timeout=15, allow_redirects=False)
        if r_verify.status_code != 200:
            raise RuntimeError(f"Logto: password verification failed: {r_verify.status_code} {r_verify.text[:200]}")

        verify_body = r_verify.json()
        verification_id = verify_body.get('verificationId')
        if not verification_id:
            raise RuntimeError(f"Logto: no verificationId returned: {verify_body}")

        # Step 3: Identification
        ident_url = f"{base_url}/api/experience/identification"
        r_ident = self.session.post(
            ident_url,
            json={"verificationId": verification_id},
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            timeout=15, allow_redirects=False)
        if r_ident.status_code not in (200, 204):
            raise RuntimeError(f"Logto: identification failed: {r_ident.status_code} {r_ident.text[:200]}")

        # Step 4: Submit interaction
        submit_url = f"{base_url}/api/experience/submit"
        r_submit = self.session.post(
            submit_url,
            json={},
            headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
            timeout=15, allow_redirects=False)
        if r_submit.status_code != 200:
            raise RuntimeError(f"Logto: submit failed: {r_submit.status_code} {r_submit.text[:200]}")

        submit_body = r_submit.json()
        redirect_to = submit_body.get('redirectTo', '')
        if not redirect_to:
            raise RuntimeError(f"Logto: no redirectTo returned: {submit_body}")

        # Resolve relative URL
        if not redirect_to.startswith('http'):
            redirect_to = base_url + (redirect_to if redirect_to.startswith('/') else '/' + redirect_to)

        # Step 5: Follow redirect chain to extract auth code
        code = None
        target_url = redirect_to
        for _ in range(10):
            resp = self.session.get(target_url, allow_redirects=False, timeout=15)
            location = resp.headers.get('Location', '')

            # Direct callback with ?code=...
            if location and 'code=' in location:
                q = urllib.parse.urlparse(location).query
                params = urllib.parse.parse_qs(q)
                code = params.get('code', [None])[0]
                break

            # Consent page (302 auto-grant or 200 manual consent)
            if location and 'consent' in location.lower():
                consent_url = location if location.startswith('http') else base_url + location
                consent_resp = self.session.get(consent_url, allow_redirects=False, timeout=15)
                consent_loc = consent_resp.headers.get('Location', '')
                if consent_loc:
                    if 'code=' in consent_loc:
                        q = urllib.parse.urlparse(consent_loc).query
                        params = urllib.parse.parse_qs(q)
                        code = params.get('code', [None])[0]
                        break
                    target_url = consent_loc if consent_loc.startswith('http') else base_url + consent_loc
                    continue
                # Manual consent: POST /api/interaction/consent
                if consent_resp.status_code == 200:
                    consent_post = self.session.post(
                        f"{base_url}/api/interaction/consent",
                        json={},
                        headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
                        timeout=15, allow_redirects=False)
                    post_loc = consent_post.headers.get('Location', '')
                    if post_loc and 'code=' in post_loc:
                        q = urllib.parse.urlparse(post_loc).query
                        params = urllib.parse.parse_qs(q)
                        code = params.get('code', [None])[0]
                        break
                    if post_loc:
                        target_url = post_loc if post_loc.startswith('http') else base_url + post_loc
                        continue

            # No more redirects
            if not location or resp.status_code not in (301, 302, 303, 307, 308):
                break
            target_url = location

        if not code:
            raise RuntimeError("Logto: no auth code obtained from authorization flow")

        self.last_auth_code = code

        # Exchange code for token
        token_req = self.request_generator.generate_token_request(code)
        r4 = self.session.post(token_req['url'], data=token_req['data'],
                               headers=token_req['headers'], timeout=15)
        if r4.status_code != 200:
            raise RuntimeError(f"Logto: token exchange failed: {r4.status_code} {r4.text[:200]}")

        token_data = r4.json()
        self.last_access_token = token_data.get('access_token')
        self.auth_result = token_data

        if self.last_access_token:
            ui_req = self.request_generator.generate_userinfo_request(self.last_access_token)
            _ = self._execute_request(ui_req)

        return token_data

    def _perform_authentik_auth_flow(self, oauth: Dict, base_url: str, user: str, password: str,
                                      auth_resp, auth_req: Dict):
        """Perform Authentik auth via flow executor API (identification + password stages)."""
        import re
        import urllib.parse

        json_headers = {'Accept': 'application/json', 'Content-Type': 'application/json'}

        # Extract flow URL from the authorize response (may be redirect or final URL)
        flow_url = getattr(auth_resp, 'url', '') or auth_req['url']
        if auth_resp.status_code in (302, 303):
            flow_url = auth_resp.headers.get('Location', flow_url)

        # Parse flow slug from URL like /if/flow/<slug>/?params
        parts = flow_url.split('?', 1)
        slug_match = re.search(r'/if/flow/([^/]+)', parts[0])
        if not slug_match:
            raise RuntimeError(f"Authentik: could not parse flow slug from {flow_url[:120]}")
        slug = slug_match.group(1)
        qs = ('?' + parts[1]) if len(parts) > 1 else ''
        exec_url = f"{base_url}/api/v3/flows/executor/{slug}/{qs}"

        # Stage 1: Identification
        r1 = self.session.post(exec_url,
                               json={'component': 'ak-stage-identification', 'uid_field': user},
                               headers=json_headers, allow_redirects=False, timeout=15)
        if r1.status_code == 302:
            loc = r1.headers['Location']
            self.session.get(loc if loc.startswith('http') else f"{base_url}{loc}",
                             headers=json_headers, allow_redirects=False, timeout=15)

        # Stage 2: Password
        r2 = self.session.post(exec_url,
                               json={'component': 'ak-stage-password', 'password': password},
                               headers=json_headers, allow_redirects=False, timeout=15)

        # Follow redirects to complete the flow
        for _ in range(5):
            if r2.status_code != 302:
                break
            loc = r2.headers.get('Location', '')
            if not loc:
                break
            r2 = self.session.get(loc if loc.startswith('http') else f"{base_url}{loc}",
                                  headers=json_headers, allow_redirects=False, timeout=15)

        # Re-request authorize with authenticated session to get the code
        auth_url = f"{auth_req['url']}?{urllib.parse.urlencode(auth_req['params'])}"
        r3 = self.session.get(auth_url, allow_redirects=False, timeout=15)

        # Follow redirect chain to extract code
        target = r3.headers.get('Location', '')
        code = None
        for _ in range(10):
            if not target:
                break
            if not target.startswith('http'):
                target = f"{base_url}{target}"
            if 'code=' in target:
                m = re.search(r'code=([a-f0-9\-]+)', target)
                if m:
                    code = m.group(1)
                break
            resp = self.session.get(target, allow_redirects=False, timeout=15)
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            target = resp.headers.get('Location', '')

        if not code:
            raise RuntimeError("Authentik: no auth code obtained from authorization flow")

        # Exchange code for token
        token_req = self.request_generator.generate_token_request(code)
        r4 = self.session.post(token_req['url'], data=token_req['data'],
                               headers=token_req['headers'], timeout=15)
        if r4.status_code != 200:
            raise RuntimeError(f"Authentik: token exchange failed: {r4.status_code} {r4.text[:200]}")

        token_data = r4.json()
        self.auth_result = token_data
        return token_data

    def _perform_authelia_auth_flow(self, oauth: Dict, base_url: str, user: str, password: str,
                                     target_url: str, auth_req: Dict):
        """Perform Authelia-specific authentication flow using JSON API"""
        import re
        import urllib.parse
        
        # Authelia uses JSON API for firstfactor authentication
        firstfactor_endpoint = f"{base_url}/api/firstfactor"
        
        firstfactor_data = {
            'username': user,
            'password': password,
            'keepMeLoggedIn': False,
            'targetURL': target_url
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Origin': base_url,
            'Referer': target_url
        }
        
        r2 = self.session.post(
            firstfactor_endpoint,
            json=firstfactor_data,
            headers=headers,
            timeout=15,
            allow_redirects=False
        )
        
        if r2.status_code not in (200, 302, 303):
            raise RuntimeError(f"Authelia firstfactor failed: {r2.status_code} - {r2.text[:200]}")
        
        # Re-access authorization endpoint after authentication
        r3 = self.session.get(
            auth_req['url'],
            params=auth_req['params'],
            headers=auth_req['headers'],
            timeout=15,
            allow_redirects=False
        )
        
        code = None
        if r3.status_code in (302, 303):
            loc = r3.headers.get('Location', '')
            try:
                p = urllib.parse.urlparse(loc)
                qs = urllib.parse.parse_qs(p.query)
                code = qs.get('code', [None])[0]
            except Exception:
                pass
            
            if not code:
                try:
                    self.session.get(loc, timeout=10, allow_redirects=True)
                except Exception:
                    pass
                code = self._wait_for_code(timeout=10)
        
        # Handle consent if required
        if not code and r3.status_code == 200:
            consent_endpoint = f"{base_url}/api/oidc/consent"
            consent_data = {'client_id': oauth.get('client_id', 'fuzz-client'), 'consent': 'accept'}
            try:
                r4 = self.session.post(consent_endpoint, json=consent_data, headers=headers, timeout=15, allow_redirects=False)
                if r4.status_code in (302, 303):
                    loc = r4.headers.get('Location', '')
                    p = urllib.parse.urlparse(loc)
                    qs = urllib.parse.parse_qs(p.query)
                    code = qs.get('code', [None])[0]
            except Exception:
                pass
        
        if not code:
            code = self._wait_for_code(timeout=15)
        
        if not code:
            raise RuntimeError("Authelia: Authorization code not obtained")
        
        self.last_auth_code = code
        
        # Exchange code for token
        token_req = self.request_generator.generate_token_request(code)
        r5 = self.session.post(token_req['url'], data=token_req['data'], headers=token_req['headers'], timeout=15)
        
        if r5.status_code != 200:
            raise RuntimeError(f"Authelia token exchange failed: {r5.status_code}")
        
        try:
            tj = r5.json()
            self.last_access_token = tj.get('access_token')
        except Exception:
            pass
        
        if self.last_access_token:
            ui_req = self.request_generator.generate_userinfo_request(self.last_access_token)
            _ = self._execute_request(ui_req)
    
    def _perform_keycloak_auth_flow(self, oauth: Dict, base_url: str, user: str, password: str,
                                     html: str, auth_req: Dict):
        """Perform Keycloak-specific authentication flow using HTML form"""
        import re
        import urllib.parse
        
        # Parse login form action
        m = re.search(r'<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"', html, re.IGNORECASE)
        if not m:
            m = re.search(r'<form[^>]*action="([^"]+)"', html, re.IGNORECASE)
        if not m:
            m = re.search(r'<form[^>]*action=[\'"]([^\'"]+)[\'"]', html or '', re.IGNORECASE)
        
        if not m:
            raise RuntimeError("Keycloak: Login form action not found")
        
        form_action = m.group(1)
        if form_action.startswith('/'):
            form_action = f"{base_url}{form_action}"

        hidden_fields = re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]+)"[^>]*value="([^"]*)"', html or '')
        
        login_data = {'username': user, 'password': password}
        
        for name, value in hidden_fields:
            if name not in login_data:
                login_data[name] = value
        
        try:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(form_action).query)
            for k, v in qs.items():
                if isinstance(v, list) and v and k not in login_data:
                    login_data[k] = v[0]
        except Exception:
            pass
        
        if any(hf[0] == 'rememberMe' for hf in hidden_fields) and 'rememberMe' not in login_data:
            login_data['rememberMe'] = 'on'
        if 'client_id' not in login_data:
            login_data['client_id'] = oauth.get('client_id', 'fuzz-client')

        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Origin': base_url, 'Referer': auth_req['url']}
        r2 = self.session.post(form_action, data=login_data, headers=headers, timeout=15, allow_redirects=False)
        
        if r2.status_code not in (302, 303):
            raise RuntimeError(f"Keycloak login did not redirect: {r2.status_code}")

        loc = r2.headers.get('Location', '')
        code = None
        try:
            p = urllib.parse.urlparse(loc)
            qs = urllib.parse.parse_qs(p.query)
            code = qs.get('code', [None])[0]
        except Exception:
            pass

        if not code:
            try:
                self.session.get(loc, timeout=10, allow_redirects=True)
            except Exception:
                pass
            code = self._wait_for_code(timeout=20)

        if not code:
            raise RuntimeError("Keycloak: Authorization code not obtained")

        self.last_auth_code = code

        token_req = self.request_generator.generate_token_request(code)
        r3 = self.session.post(token_req['url'], data=token_req['data'], headers=token_req['headers'], timeout=15)
        
        if r3.status_code != 200:
            raise RuntimeError(f"Keycloak token exchange failed: {r3.status_code}")

        try:
            tj = r3.json()
            self.last_access_token = tj.get('access_token')
        except Exception:
            pass

        if self.last_access_token:
            ui_req = self.request_generator.generate_userinfo_request(self.last_access_token)
            _ = self._execute_request(ui_req)

    def _execute_request(self, request: Dict) -> Dict:
        """Execute HTTP request and return response data"""
        try:
            method = request['method']
            url = request['url']
            headers = request.get('headers', {})
            params = request.get('params')
            data = request.get('data')
            
            if method == 'GET':
                response = self.session.get(url, params=params, headers=headers, timeout=10)
            elif method == 'POST':
                response = self.session.post(url, data=data, headers=headers, timeout=10)
            else:
                response = self.session.request(method, url, headers=headers, timeout=10)
            
            body_text = response.text if response.text else ''
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'content_type': response.headers.get('content-type', ''),
                'response_time': time.time(),
                'url': response.url,
                'body': body_text[:1000],
                'content_preview': body_text[:200]
            }
            
        except Exception as e:
            return {
                'status_code': 0,
                'error': str(e),
                'response_time': time.time()
            }
    
    def _get_current_coverage(self) -> CoverageData:
        """Get current coverage data (target-aware)."""
        # State-based targets: use GoCoverageManager directly
        if self.target_type in ('authelia', 'casdoor', 'ory_hydra', 'zitadel', 'authentik', 'simplelogin', 'nodeoidc', 'logto'):
            go_cov = getattr(self, 'go_coverage', None)
            if go_cov:
                try:
                    go_data = go_cov.collect_coverage()
                    if go_data:
                        return go_data
                except Exception:
                    pass
            return CoverageData()

        # Keycloak: use JaCoCo
        if self.jacoco is None:
            return CoverageData()

        xml_file = self.jacoco.generate_report()
        if xml_file:
            try:
                print(f"[Coverage] Parsing XML: {xml_file} (exists={os.path.exists(xml_file)})")
            except Exception:
                pass
            return self.jacoco.parse_coverage_xml(xml_file)

        return CoverageData()

    def _get_state_based_coverage(self) -> CoverageData:
        """Get Go coverage for Authelia targets via GoCoverageManager."""
        go_cov = getattr(self, 'go_coverage', None)
        if go_cov:
            try:
                go_data = go_cov.collect_coverage()
                if go_data:
                    return go_data
            except Exception:
                pass
        return CoverageData()

    def _has_new_coverage(self, response_data: Dict) -> bool:
        """Check if response indicates new coverage"""
        # Get current coverage
        self.current_coverage = self._get_current_coverage()
        
        # Check for coverage increase
        coverage_increase = (
            self.current_coverage.instructions_covered > self.baseline_coverage.instructions_covered or
            self.current_coverage.lines_covered > self.baseline_coverage.lines_covered or
            self.current_coverage.branches_covered > self.baseline_coverage.branches_covered
        )
        
        # Check for interesting response patterns
        interesting_response = self._is_interesting_response(response_data)
        
        return coverage_increase or interesting_response
    
    def _is_interesting_response(self, response_data: Dict) -> bool:
        """Check if response is interesting based on patterns"""
        status_code = response_data.get('status_code', 0)

        # Before this fix every 4xx/5xx was flagged, which flooded the log
        # with 404/501 misrouting noise.  Narrow to genuine anomalies: server
        # errors (5xx != 501 from stale mock listeners), network failures,
        # and abnormally large bodies.  4xx responses are ordinary OAuth
        # validation paths and should not be treated as interesting.
        if status_code >= 500 and status_code != 501:
            return True
        if status_code == 0:  # network / timeout
            return True

        content_length = response_data.get('content_length', 0)
        if content_length > 1_000_000:
            return True

        content_type = response_data.get('content_type', '')
        if 'application/json' in content_type and 'error' in response_data.get('content_preview', ''):
            return True

        return False
    
    def _save_interesting_case(self, request: Dict, response_data: Dict, coverage_data: CoverageData):
        """Record an interesting case.

        By default this appends a one-line JSON record to sequences.jsonl
        (streamlined log) and does NOT write a per-case JSON file.  Set
        fuzzing.save_interesting_cases=true in the config to also emit the
        legacy interesting_case_NNNNNN.json artefacts for offline replay.
        """
        case = {
            'request': request,
            'response': response_data,
            'coverage': {
                'instructions_covered': coverage_data.instructions_covered,
                'instructions_total': coverage_data.instructions_total,
                'coverage_percentage': coverage_data.coverage_percentage
            },
            'timestamp': time.time(),
            'execution_count': self.execution_count
        }

        # Keep a bounded in-memory summary count only (do not accumulate all
        # records — would drive RSS up on long runs).
        self.interesting_cases.append({
            'execution_count': self.execution_count,
            'timestamp': case['timestamp'],
            'status_code': response_data.get('status_code', 0),
            'coverage_percentage': coverage_data.coverage_percentage,
        })

        if self._save_interesting_cases:
            output_dir = self.config.get('output_dir', 'out/oauth_fuzz')
            os.makedirs(output_dir, exist_ok=True)
            case_file = os.path.join(
                output_dir,
                f"interesting_case_{len(self.interesting_cases):06d}.json"
            )
            try:
                with open(case_file, 'w') as f:
                    json.dump(case, f, indent=2)
                print(f"Saved interesting case: {case_file}")
                print(f"  Coverage: {coverage_data.coverage_percentage:.2f}%")
                print(f"  Status: {response_data.get('status_code', 'ERROR')}")
            except Exception as e:
                print(f"[SeqLog] Failed to write case file: {e}")

    def _log_sequence_result(self, endpoint_type: str, request: Dict,
                             response_data: Dict, coverage_pct: float,
                             coverage_delta: float, is_new_coverage: bool):
        """Append a compact one-line record of (sequence, result) to
        sequences.jsonl.  This is the primary fuzzing artefact — it captures
        what request went where and what happened, with coverage delta, in
        a form that is grep-/jq-/wc-friendly.
        """
        if not self._sequence_log_fh:
            return
        try:
            record = {
                'iter':         self.execution_count,
                'ts':           round(time.time(), 3),
                'endpoint':     endpoint_type,
                'method':       request.get('method'),
                'url':          request.get('url'),
                'status':       response_data.get('status_code', 0),
                'resp_bytes':   response_data.get('content_length', 0),
                'cov_pct':      round(coverage_pct, 4),
                'cov_delta':    round(coverage_delta, 4),
                'new_cov':      bool(is_new_coverage),
            }
            self._sequence_log_fh.write(json.dumps(record, separators=(',', ':')) + '\n')
        except Exception:
            # Never let logging break the fuzz loop
            pass

    def fuzz(self, max_iterations: int = 1000):
        """Main fuzzing loop with coverage feedback"""
        print(f"Starting OAuth fuzzing with Java coverage integration...")
        print(f"Max iterations: {max_iterations}")
        
        start_time = time.time()
        
        for iteration in range(max_iterations):
            self.execution_count += 1
            
            # 周期性执行完整授权码流程，刷新 token 与会话
            if iteration % 50 == 0:
                try:
                    self._perform_authorization_code_flow()
                except Exception:
                    pass

            endpoint_pool = ['authorize', 'token', 'userinfo', 'openid_config', 'jwks']
            if self.last_access_token:
                endpoint_pool.append('introspect')

            endpoint_type = random.choice(endpoint_pool)
            if endpoint_type == 'authorize':
                base_request = self.request_generator.generate_authorize_request()
            elif endpoint_type == 'token':
                if self.last_auth_code:
                    base_request = self.request_generator.generate_token_request(self.last_auth_code)
                else:
                    base_request = self.request_generator.generate_password_grant_request()
            elif endpoint_type == 'userinfo':
                if self.last_access_token:
                    base_request = self.request_generator.generate_userinfo_request(self.last_access_token)
                else:
                    base_request = self.request_generator.generate_authorize_request()
            elif endpoint_type == 'openid_config':
                base_request = self.request_generator.generate_openid_config_request()
            elif endpoint_type == 'jwks':
                base_request = self.request_generator.generate_jwks_request()
            else:  # introspect
                base_request = self.request_generator.generate_introspect_request(self.last_access_token) if self.last_access_token else self.request_generator.generate_authorize_request()
            
            mutated_request = self.request_generator.mutate_request(base_request)
            self.mutation_count += 1
            
            response_data = self._execute_request(mutated_request)

            # Track response for state-based targets (Authelia, Logto, etc.)
            # This records endpoint hits, status codes, error patterns, and
            # unique state signatures used by GoCoverageManager.collect_coverage().
            _STATE_BASED = ('authelia', 'casdoor', 'ory_hydra', 'zitadel',
                            'authentik', 'simplelogin', 'nodeoidc', 'logto')
            if self.target_type in _STATE_BASED and self.go_coverage:
                try:
                    self.go_coverage.track_response(response_data, endpoint=endpoint_type)
                except Exception:
                    pass

            # 成功 token 响应更新 access_token
            if endpoint_type in ('token',) and response_data.get('status_code') == 200:
                try:
                    r = self.session.post(mutated_request['url'], data=mutated_request.get('data'), headers=mutated_request.get('headers', {}), timeout=10)
                    tj = r.json()
                    if 'access_token' in tj:
                        self.last_access_token = tj['access_token']
                except Exception:
                    pass

            # Throttled coverage dump: calling dump_coverage + generate_report
            # every iteration dominated wall time and produced no finer signal
            # than sampling every _dump_every_n iterations.
            coverage_refreshed = False
            if self.jacoco and (iteration % self._dump_every_n == 0):
                try:
                    jp = self.config.get('jacoco', {}).get('agent_port', 6300)
                    self.jacoco.dump_coverage(port=jp)
                    coverage_refreshed = True
                except Exception as e:
                    if iteration == 0:
                        print(f"[Coverage] dump failed (iter=0): {e}")
            elif self.target_type in _STATE_BASED and self.go_coverage:
                # State-based targets: refresh coverage from tracked states
                # every _dump_every_n iterations (no external dump needed).
                if iteration % self._dump_every_n == 0:
                    coverage_refreshed = True

            is_new_cov = False
            coverage_delta = 0.0
            if coverage_refreshed:
                prev_pct = self._last_coverage_pct
                is_new_cov = self._has_new_coverage(response_data)
                coverage_delta = self.current_coverage.coverage_percentage - prev_pct
                self._last_coverage_pct = self.current_coverage.coverage_percentage
                if is_new_cov and self.current_coverage.instructions_covered > self.baseline_coverage.instructions_covered:
                    self._save_interesting_case(mutated_request, response_data, self.current_coverage)
                    self.baseline_coverage = self.current_coverage
                    print(f"[Coverage] Growth at iter={iteration}: "
                          f"{self.baseline_coverage.coverage_percentage:.2f}% "
                          f"(+{coverage_delta:+.2f}%)")
            else:
                # Non-refresh iteration: still flag interesting anomalies
                # (5xx, network errors) but do NOT call _has_new_coverage
                # (which would trigger a report regeneration).
                if self._is_interesting_response(response_data):
                    self._save_interesting_case(mutated_request, response_data, self.current_coverage)

            # Always record the sequence/result pair in the rolling JSONL.
            self._log_sequence_result(
                endpoint_type=endpoint_type,
                request=mutated_request,
                response_data=response_data,
                coverage_pct=self._last_coverage_pct,
                coverage_delta=coverage_delta,
                is_new_coverage=is_new_cov,
            )

            if iteration and iteration % 50 == 0:
                elapsed = time.time() - start_time
                rate = self.execution_count / elapsed if elapsed > 0 else 0
                print(f"[iter={iteration:4d}] cov={self._last_coverage_pct:.2f}%  "
                      f"rate={rate:.1f} exec/s  sequences={self.execution_count}")

            if time.time() - start_time > self.config.get('fuzzing', {}).get('timeout_seconds', 3600):
                print("Fuzzing timeout reached")
                break
        
        elapsed = time.time() - start_time
        # Close the streaming log cleanly so the last buffered record is on disk.
        try:
            if self._sequence_log_fh:
                self._sequence_log_fh.flush()
                self._sequence_log_fh.close()
                self._sequence_log_fh = None
        except Exception:
            pass
        print(f"\nFuzzing completed:")
        print(f"  Total executions: {self.execution_count}")
        print(f"  Interesting cases: {len(self.interesting_cases)}")
        print(f"  Sequence log:    {self._sequence_log_path}")
        print(f"  Final coverage: {self.current_coverage.coverage_percentage:.2f}%")
        print(f"  Execution rate: {self.execution_count / elapsed:.1f} execs/sec")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='OAuth fuzzer with Java coverage')
    parser.add_argument('config', help='Configuration JSON file')
    parser.add_argument('--iterations', type=int, default=1000, help='Max iterations')
    
    args = parser.parse_args()
    
    # Load configuration
    with open(args.config, 'r') as f:
        config = json.load(f)
    
    # Create and run fuzzer
    fuzzer = OAuthFuzzerWithCoverage(config)
    fuzzer.fuzz(args.iterations)
