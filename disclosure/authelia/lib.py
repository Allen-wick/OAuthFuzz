#!/usr/bin/env python3
"""
Low-level Authelia OAuth/OIDC PoC helper library.
Gives precise control over each request (no auto-redirect, raw status/Location/bodies)
for the multi-round dynamic verification.
"""
import os, base64, hashlib, secrets, json
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = os.environ.get("AUTHELIA_BASE", "https://127.0.0.1:9091")
CLIENTS = {
    "fuzz-client":  {"secret": "fuzz-client-secret",  "redirect": "https://127.0.0.1:7777/callback", "public": False},
    "fuzz-preconf": {"secret": "fuzz-preconf-secret", "redirect": "https://127.0.0.1:7777/callback", "public": False},
    "fuzz-public":  {"secret": None,                  "redirect": "http://127.0.0.1:8888/callback",  "public": True},
    "fuzz-client2": {"secret": "fuzz-client2-secret", "redirect": "https://127.0.0.1:7778/callback", "public": False},
}
USERS = {"testuser": "testpass", "victim": "victimpass"}


def S():
    s = requests.Session()
    s.verify = False
    return s


# ---------- PKCE ----------
def pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


# ---------- 1FA login ----------
def login(s, username="testuser", password="testpass"):
    r = s.post(f"{BASE}/api/firstfactor",
               json={"username": username, "password": password, "keepMeLoggedIn": False},
               headers={"Content-Type": "application/json"}, allow_redirects=False)
    return r


# ---------- consent (required e.g. for offline_access / explicit / pre-configured modes) ----------
def extract_flow_id(location):
    from urllib.parse import urlparse, parse_qs
    return parse_qs(urlparse(location).query).get("flow_id", [None])[0]


def needs_consent(location):
    return bool(location) and "/consent/openid/decision" in location


def complete_consent(s, authorize_resp, client_id, pre_configure=False, claims=None):
    """POST /api/oidc/consent to grant, then GET the returned redirect_uri to obtain the code."""
    flow_id = extract_flow_id(authorize_resp.headers.get("Location"))
    body = {"flow_id": flow_id, "client_id": client_id, "consent": True,
            "pre_configure": pre_configure, "claims": claims or []}
    r = s.post(f"{BASE}/api/oidc/consent", json=body,
               headers={"Content-Type": "application/json"}, allow_redirects=False)
    j = r.json()
    redirect_uri = (j.get("data") or {}).get("redirect_uri") or j.get("redirect_uri")
    # re-enter authorization with consent_id -> 302 to client redirect_uri with the code
    return s.get(redirect_uri, allow_redirects=False), r


# ---------- authorize ----------
def authorize(s, client_id, scope="openid profile", state="state0123456789abcdef", extra=None,
              redirect=None, allow_redirects=False):
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect or CLIENTS[client_id]["redirect"],
        "scope": scope,
        "state": state,
    }
    if extra:
        params.update(extra)
    return s.get(f"{BASE}/api/oidc/authorization", params=params, allow_redirects=allow_redirects)


def parse_code(location):
    """Extract code (or error) from a Location header query string."""
    if not location:
        return None, None
    from urllib.parse import urlparse, parse_qs
    q = parse_qs(urlparse(location).query)
    if "code" in q:
        return "code", q["code"][0]
    if "error" in q:
        return "error", q["error"][0]
    return None, location


# ---------- token exchange ----------
def token(s, data, client_id=None, client_secret=None, basic=False):
    """POST /api/oidc/token. If client_id/secret given and not basic, put in form body (client_secret_post)."""
    form = dict(data)
    if client_id is not None and not basic:
        form.setdefault("client_id", client_id)
        if client_secret is not None:
            form.setdefault("client_secret", client_secret)
    auth = (client_id, client_secret) if (basic and client_id and client_secret is not None) else None
    return s.post(f"{BASE}/api/oidc/token", data=form, auth=auth, allow_redirects=False)


# ---------- full happy-path helper ----------
def get_tokens(client_id="fuzz-client", username="testuser", password="testpass",
               scope="openid profile", pkce=False, extra_auth=None, pre_configure_consent=False):
    """Run 1FA -> authorize -> token. Returns (session, code, token_json, authorize_resp)."""
    s = S()
    lr = login(s, username, password)
    assert lr.status_code == 200, f"login failed: {lr.status_code} {lr.text[:200]}"
    extra = dict(extra_auth or {})
    if pkce:
        verifier, challenge = pkce_pair()
        extra["code_challenge"] = challenge
        extra["code_challenge_method"] = "S256"
    ar = authorize(s, client_id, scope=scope, extra=extra)
    loc = ar.headers.get("Location")
    if needs_consent(loc):
        ar, _ = complete_consent(s, ar, client_id, pre_configure=pre_configure_consent)
        loc = ar.headers.get("Location")
    kind, val = parse_code(loc)
    assert kind == "code", f"no code in authorize (status={ar.status_code}, loc={loc}, body={ar.text[:200]})"
    code = val
    form = {"grant_type": "authorization_code", "code": code,
            "redirect_uri": CLIENTS[client_id]["redirect"]}
    if pkce:
        form["code_verifier"] = verifier
    tr = token(s, form, client_id=client_id,
               client_secret=CLIENTS[client_id]["secret"])
    return s, code, tr


def b64url_decode(seg):
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def jwt_payload(tok):
    try:
        return json.loads(b64url_decode(tok.split(".")[1]))
    except Exception as e:
        return {"_decode_error": str(e)}


if __name__ == "__main__":
    # smoke test (PKCE required globally - C2 behavior)
    s, code, tr = get_tokens(pkce=True)
    print("LOGIN+AUTHCODE+TOKEN smoke test (fuzz-client, implicit consent, PKCE)")
    print("  code:", code[:24], "...")
    print("  token status:", tr.status_code)
    data = tr.json()
    print("  has access_token:", "access_token" in data)
    print("  has id_token:", "id_token" in data)
    print("  has refresh_token:", "refresh_token" in data)
    print("  scope:", data.get("scope"))
    print("  id_token sub:", jwt_payload(data.get("id_token", "")).get("sub"))
