# Apache CXF — CVE Submission Packet (C24 / C25 / C26 / C27 / C28)

**Prepared:** 2026-07-08
**Product:** Apache CXF — `cxf-rt-rs-security-oauth2-saml` (C24, C26-SAML),
`cxf-rt-rs-security-oauth2` (C25, C26-JWT, C27), `cxf-rt-rs-security-sso-oidc` (C28)
**Confirmed-affected versions:** Apache CXF **3.5.7** (binary, verified) and the **4.2.x** source
line through **4.2.2-SNAPSHOT** (development head; latest GA releases are **4.2.1 / 4.1.6 / 3.6.11**,
2026-05-20).
**Not addressed by** the 2026-06-11 advisory batch (CVE-2026-50623/27/28/29/30/31), nor by
CVE-2021-22696 (`request_uri` SSRF — a different code path) — see § Novelty per finding.
**Submission target:** Apache CXF Security Team — **security@cxf.apache.org** (Apache is a CNA).
Coordinated disclosure; 90-day embargo proposed.

---

## How to use this packet

1. Fill in the **Reporter** block.
2. Email §A–§E to `security@cxf.apache.org`, attaching the PoC sources referenced in each section
   and `poc_harness/round3_harness_output.txt`.
3. The ASF security team assigns CVE numbers, confirms exact introduced/fixed versions, and
   coordinates a release fix + advisory.

### Reporter
- **Name / affiliation:** `<to be filled>`
- **Contact:** `<email>`
- **Disclosure intent:** coordinated (90-day embargo proposed).
- **Credit name for advisory:** `<as desired>`

### Affected-version determination (methodology)
- **Static:** source inspection of `cxf-main` @ `4.2.2-SNAPSHOT`.
- **Binary:** `javap -p/-c` on the released 3.5.7 jars confirms the vulnerable code shapes.
- **Exclusion:** none of the 2026-06-11 fixes (introspection throw, JWT aud/iss, IP-binding,
  log-injection, response-splitting, refresh-TOCTOU) touch these five code paths → presumed
  **unfixed in 4.2.1 / 4.1.6 / 3.6.11**. CXF team to confirm exact bounds.

---

## §A — C24: SAML Bearer Accepts Unsigned Assertion Under mTLS With No Holder-of-Key Binding

**Proposed title:** Apache CXF: OAuth2 SAML-bearer grant accepts an unsigned SAML assertion under
mutual TLS without binding the assertion Subject to the client certificate

**Vulnerability type:** CWE-287 (Improper Authentication) / CWE-345 (Insufficient Verification of
Data Authenticity)

**Affected component:** `cxf-rt-rs-security-oauth2-saml` — `grants/saml/Saml2BearerGrantHandler.java`

**Affected versions:** confirmed 3.5.7 and 4.2.x through 4.2.2-SNAPSHOT; bounds TBD.

### Description (CVE prose)
In Apache CXF's SAML2-bearer grant handler, when the token request arrives over mutual TLS, an
**unsigned** SAML assertion is accepted (the `else if (getTLSCertificates(message) == null)` branch
that would reject it is not taken) and the assertion's self-declared `<Subject>` is trusted
verbatim — there is no check that the assertion Subject corresponds to the mTLS client identity, and
no Holder-of-Key binding between the assertion and the presented certificate. Any client that
possesses *some* mTLS certificate accepted by the AS can therefore forge an unsigned SAML assertion
naming an arbitrary subject and redeem it for an access token, impersonating that subject. The mTLS
cert is treated as "presence of a cert" rather than "proof of *this* subject."

### CVSS v3.1 (recommended)
**5.9 — MEDIUM**  `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N`

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | token endpoint is network-reachable |
| Attack Complexity | High | requires mTLS enabled on the token endpoint + a client cert the AS accepts |
| Privileges Required | None | any accepted mTLS cert |
| User Interaction | None | — |
| Scope | Unchanged | within the AS trust domain |
| Confidentiality | High | impersonate an arbitrary subject named in the forged assertion |

### Proof of Concept
**G5△ (static — mTLS-gated):** dynamic reproduction requires an mTLS-enabled token endpoint (the
fuzz harness uses client-secret auth). The root cause is established from source.

**Vulnerable code (`oauth2-saml/.../grants/saml/Saml2BearerGrantHandler.java`):**
```java
if (assertion.isSigned()) {
    ...verifySignature(samlKeyInfo);
    assertion.parseSubject(...);
} else if (getTLSCertificates(message) == null) {
    throw new OAuthServiceException(OAuthConstants.INVALID_GRANT);
}
// else: UNSIGNED assertion silently accepted — the Subject is then taken verbatim from
// the (unsigned, attacker-controlled) assertion, with no binding to the mTLS client cert.
```

### Security impact
Subject impersonation on mTLS-enabled SAML-bearer deployments: a holder of any accepted mTLS
certificate mints tokens for arbitrary subjects without a signed assertion or a key-binding proof.

### Suggested fix
In the unsigned-assertion branch, require the assertion `<Subject>` to match the mTLS client
identity (Holder-of-Key), or reject unsigned assertions at the grant endpoint.

### Workaround (pre-fix)
Require SAML bearer assertions to be signed (`assertion.isSigned()` enforced) and do not rely on the
mTLS-unsigned-assertion branch.

### Novelty / prior art (G7)
No existing CXF CVE covers the unsigned-SAML-under-mTLS path. CVE-2015-5253 (CXF SAML) concerns
assertion wrapping in Fediz — a different component/root cause.

---

## §B — C25: JAR `request` JWT Silently Overrides `code_challenge` / `nonce` (PKCE Weakening)

**Proposed title:** Apache CXF: OAuth2 JAR (`request` parameter) lets a signed request JWT override
security-sensitive authorization parameters (code_challenge, code_challenge_method, nonce) without
re-validation

**Vulnerability type:** CWE-20 (Improper Input Validation) / CWE-345 (Insufficient Verification of
Data Authenticity)

**Affected component:** `cxf-rt-rs-security-oauth2` — `grants/code/JwtRequestCodeFilter.java`

**Affected versions:** confirmed 3.5.7 and 4.2.x through 4.2.2-SNAPSHOT; bounds TBD.

### Description (CVE prose)
In Apache CXF's JAR (RFC 9101) request filter, after the `request` JWT's signature, `iss`,
`client_id`, and `response_type` are validated, `process()` writes **every** claim from the request
JWT into the authorization parameters via `putSingle` (silent override) with no per-parameter
re-validation. Consequently a signed `request` JWT can replace the client's outer `code_challenge`,
`code_challenge_method`, `nonce`, and `claims` values with attacker-chosen ones. (`redirect_uri`,
`scope`, and `audience` ARE re-validated downstream; the gap is the PKCE/nonce/claims set.) Per
RFC 9101 §2.2 these parameters must be carried in the outer request, not silently overridden by the
JWT — the attacker who can produce a validly-signed request JWT for a client (e.g., a malicious
client, or a compromised `client_secret` used as the HMAC key) controls the enforced PKCE challenge.

### CVSS v3.1 (recommended)
**4.1 — MEDIUM (low end)**  `AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N`

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | authorization endpoint is network-reachable |
| Attack Complexity | High | requires JAR enabled for the client + a validly-signed request JWT |
| Privileges Required | Low | a registered client (or a compromised shared secret) |
| User Interaction | None | (impact realized when the authorization flow runs) |
| Scope | Unchanged | — |
| Confidentiality / Integrity | Low | attacker controls the PKCE challenge; enables PKCE weakening / code-substitution assist |

> G2△: gated on JAR being enabled for the client (the request-JWT signature must verify). Combined
> with a redirect-interception capability this can assist authorization-code capture; the direct
> impact is PKCE-value control.

### Proof of Concept
**Source:** `validate/targets/cxf/poc_harness/src/main/java/cxfpoc/C25_JarRequestOverride.java`
(real CXF 3.5.7 `JwtRequestCodeFilter.process`). Run via `run_all_round3.sh`.

Steps: outer request carries `code_challenge=legit-client-challenge`, `code_challenge_method=plain`;
a signed `request` JWT carries `code_challenge=EVIL-CHALLENGE-CONTROLLED-BY-JWT`, `method=S256`.
Call `filter.process(params, null, client)`.

**Verbatim result:**
```
outer request:  code_challenge=legit-client-challenge, code_challenge_method=plain
signed request JWT claim: code_challenge=EVIL-CHALLENGE-CONTROLLED-BY-JWT, method=S256
AFTER JwtRequestCodeFilter.process():
  code_challenge        = EVIL-CHALLENGE-CONTROLLED-BY-JWT
  code_challenge_method = S256
=> C25 CONFIRMED — the signed request JWT silently overrode the client's outer code_challenge
   and method (no re-validation); PKCE value is attacker-controllable via JAR.
```

**Vulnerable code (`grants/code/JwtRequestCodeFilter.java:96-110`):**
```java
MultivaluedMap<String, String> newParams = new MetadataMap<>(params);
Map<String, Object> claimsMap = claims.asMap();
for (Map.Entry<String, Object> entry : claimsMap.entrySet()) {
    ...
    newParams.putSingle(key, value.toString());   // blanket override; iss/client_id/response_type
}                                                 // are checked above, code_challenge/nonce are NOT
return newParams;
```

### Security impact
PKCE weakening / authorization-parameter tampering: the enforced `code_challenge`/`method`/`nonce`
can be set by an attacker who can sign a request JWT for the client, undermining the PKCE and
replay protections the client intended (RFC 9101 §2.2, RFC 7636).

### Suggested fix
Ignore (or reject) security-sensitive claims (`code_challenge`, `code_challenge_method`, `nonce`,
`state`, `client_id`, `redirect_uri`) inside the `request` JWT; treat the outer request as
authoritative for them, per RFC 9101 §2.2.

### Workaround (pre-fix)
Disable JAR (`request`/`request_uri` processing) for clients where the request-JWT signing key is
not strictly controlled, or wrap `JwtRequestCodeFilter` with a subclass that re-validates
overridden PKCE/nonce params.

### Novelty / prior art (G7)
**Distinct from CVE-2021-22696**, which is the `request_uri` *fetch* not being validated (SSRF).
C25 is the *inline `request` parameter* silently overriding PKCE/nonce — a different code path
(`JwtRequestCodeFilter.process` override loop vs. the `request_uri` fetch). No existing CXF CVE
covers JAR parameter override.

---

## §C — C26: SAML & JWT Bearer Grants Have No Replay Cache

**Proposed title:** Apache CXF: OAuth2 SAML-bearer and JWT-bearer grants accept replayed
assertions (no jti / assertion-ID replay cache)

**Vulnerability type:** CWE-294 (Authentication Bypass by Capture-replay)

**Affected component:** `cxf-rt-rs-security-oauth2-saml` (`SamlOAuthValidator.java`) and
`cxf-rt-rs-security-oauth2` (`grants/jwt/AbstractJwtHandler.java`)

**Affected versions:** confirmed 3.5.7 and 4.2.x through 4.2.2-SNAPSHOT; bounds TBD.

### Description (CVE prose)
Neither the SAML-bearer nor the JWT-bearer grant handler records the assertion identifier in a
replay cache. The SAML validator validates `NotOnOrAfter` but leaves a `//TODO: replay cache`
unimplemented; the JWT-bearer validator never reads the `jti` claim. A captured bearer assertion is
therefore redeemable any number of times within its validity window, each redemption minting a
fresh, independent access token for the assertion's subject. This violates the one-time-use
semantics expected of bearer assertions (RFC 7521 §2.1, RFC 7523). Distinct from CVE-2026-50631
(refresh-token TOCTOU) and the authorization-code replay issue: this is outright absence of replay
protection on the bearer-grant paths.

### CVSS v3.1 (recommended)
**5.3 — MEDIUM**  `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (recommended range 5.3–7.4; CNA to decide)

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | token endpoint is network-reachable |
| Attack Complexity | High | requires a captured bearer assertion (network MITM / log exposure) |
| Privileges Required | None | — |
| User Interaction | None | — |
| Scope | Unchanged | within the AS trust domain |
| Confidentiality / Integrity | High | each replay mints a token for the assertion's subject (impersonation) |

> The captured-assertion precondition is modeled as AC:H. **Compounds C21** (SAML Address check
> disabled) and **C24** (unsigned SAML under mTLS): together a captured/forgeable bearer assertion
> is replayable indefinitely.

### Proof of Concept
**Source:** `validate/targets/cxf/poc_harness/src/main/java/cxfpoc/C26_JwtBearerReplay.java` (real
CXF 3.5.7 `JwtBearerGrantHandler`). Run via `run_all_round3.sh`.

Steps: forge a validly-signed JWT-bearer assertion with a stable `jti=assertion-12345`; redeem it
5 times.

**Verbatim result:**
```
redemption #1 -> token dcca1dfb9a70d470...
redemption #2 -> token f16b31ed62d7ae3d...
redemption #3 -> token 1d726ff7f47a2db8...
redemption #4 -> token 143e25bf4af4beaf...
redemption #5 -> token 92a9a1bbb781121c...
distinct access tokens minted from ONE assertion (jti=assertion-12345): 5
=> C26 CONFIRMED — no jti/replay cache; the same bearer assertion was redeemed 5x, each minting
   a distinct access token (RFC 7523 one-time-use violated).
```

**Vulnerable code:**
`SamlOAuthValidator.java:160-166` — `//TODO: replay cache, same as with SAML SSO case` (absent);
`grants/jwt/AbstractJwtHandler.validateClaims:59-72` — `jti` never read/cached.

### Security impact
Unbounded replay of captured bearer assertions → repeated token issuance for the assertion's
subject (impersonation). Each replay yields a fresh access token, defeating one-time-use
expectations and any per-assertion rate accounting.

### Suggested fix
Enforce a single-use replay cache keyed on the assertion ID / `jti` (the SAML SSO path already uses
a `ONE_TIME_USE` cache — reuse it for the bearer grants).

### Workaround (pre-fix)
Front the bearer grant handlers with a custom validator that records `jti`/assertion-ID in a
short-TTL replay cache and rejects duplicates; keep bearer-assertion lifetimes short.

### Novelty / prior art (G7)
No existing CXF CVE addresses bearer-grant replay caches. Distinct from CVE-2026-50631
(refresh-token TOCTOU race) — this is the outright absence of replay protection on the
SAML/JWT-bearer grant paths.

---

## §D — C27: `JwtAccessTokenValidator` Does Not Enforce `exp` / `nbf`   ⚠ WITHDRAWN (2026-07-18)

> **Vendor (Apache CXF security team) confirmed C27 is already fixed by CVE-2026-50627
> (PR [apache/cxf#3126](https://github.com/apache/cxf/pull/3126); fixed in ≥ 4.2.2 / 4.1.7).**
> Although CVE-2026-50627's title says "Audience and Issuer", PR #3126 adds a `validateToken`
> override that calls `JwtUtils.validateTokenClaims(...)`, enforcing **iss/exp/nbf/iat/aud** — the
> PR's tests (`testValidateAccessTokenExpired`, `testValidateAccessTokenNotBefore`) confirm `exp`/`nbf`
> are rejected. **Do not submit §D as a new CVE.** The section is retained below for the record.

**Proposed title:** Apache CXF: OAuth2 resource-server JwtAccessTokenValidator does not enforce JWT
access-token `exp` / `nbf`, accepting expired tokens

**Vulnerability type:** CWE-613 (Insufficient Session Expiration) / CWE-754 (Improper Check for
Unusual Conditions)

**Affected component:** `cxf-rt-rs-security-oauth2` — `filters/JwtAccessTokenValidator.java`

**Affected versions:** confirmed 3.5.7 and 4.2.x through 4.2.2-SNAPSHOT; bounds TBD.

### Description (CVE prose)
At the resource server, `JwtAccessTokenValidator.validateAccessToken` verifies the JWT signature and
maps claims into an `AccessTokenValidation`, but the `exp` claim is read only to compute a
token-lifetime *number* — it is never compared to the current time — and `nbf` is never checked.
(`JoseJwtConsumer.validateToken` is an empty no-op.) A JWT access token whose `exp` is in the past
(or which omits `exp`) is therefore accepted at the resource server, granting access beyond the
token's intended lifetime (or indefinitely when `exp` is absent).

### CVSS v3.1 (recommended)
**5.3 — MEDIUM**  `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | resource server is network-reachable |
| Attack Complexity | Low | present a captured expired (or no-`exp`) JWT access token |
| Privileges Required | None | — |
| User Interaction | None | — |
| Scope | Unchanged | within the RS trust domain |
| Confidentiality | Low | continued access to resources the token authorizes, past expiry |

> **Compounds C20** (id_token accepted as access token): an id_token whose `exp` is short — and
> which the RS never validates — remains usable indefinitely as an access token.

### Proof of Concept
**Source:** `validate/targets/cxf/poc_harness/src/main/java/cxfpoc/C20_C27_JwtAccessTokenValidator.java`
(the C27 sub-test, real CXF 3.5.7 `JwtAccessTokenValidator`). Run via `run_all_round3.sh`.

Steps: build a JWT with `exp = now - 3600` (expired 1 h ago); call
`validator.validateAccessToken(null, "Bearer", expJwt, null)`.

**Verbatim result:**
```
validateAccessToken(EXPIRED jwt, exp=now-3600) -> ACCEPTED (no exp enforcement)
=> C27 CONFIRMED — JwtAccessTokenValidator does not enforce exp/nbf; an expired JWT access
   token is accepted (absent exp ⇒ never-expiring).
```

**Vulnerable code (`filters/JwtAccessTokenValidator.java:68-131`):** `exp` is read into a lifetime
number; `convertClaimsToValidation` performs no `now` comparison; `validateToken()` is empty.

### Security impact
Extended/unbounded resource access via expired or no-`exp` JWT access tokens; defeats session
expiration at any resource server using local JWT validation.

### Suggested fix
In `JwtAccessTokenValidator`, enforce `exp`/`nbf` (or route through
`AbstractAccessTokenValidator.isExpired`) and require `exp` to be present.

### Workaround (pre-fix)
On resource servers, prefer opaque-token introspection over local JWT validation until `exp`/`nbf`
enforcement is added; or wrap the validator to reject absent/past `exp`.

### Novelty / prior art (G7)
**Distinct from CVE-2026-50627** (JWT access-token **aud/iss** not validated = registry C9).
CVE-2026-50627 concerns audience/issuer; C27 concerns **expiry/not-before** enforcement — an
orthogonal claim-validation gap in the same validator. Whether the CVE-2026-50627 fix also added
`exp`/`nbf` enforcement must be confirmed against the patched source; if not, C27 remains
exploitable on 50627-patched versions.

---

## §E — C28: Self-Issued Provider Routes id_token to Empty Validator

**Proposed title:** Apache CXF: OIDC RP `OidcClaimsValidator` routes self-issued (`https://self-issued.me`)
id_tokens to an empty validation method, skipping audience/subject/expiry checks

**Vulnerability type:** CWE-347 (Improper Verification of Cryptographic Signature) / CWE-345
(Insufficient Verification of Data Authenticity)

**Affected component:** `cxf-rt-rs-security-sso-oidc` — `rp/OidcClaimsValidator.java`

**Affected versions:** confirmed 3.5.7 and 4.2.x through 4.2.2-SNAPSHOT; bounds TBD.

### Description (CVE prose)
In Apache CXF's OIDC relying-party claims validator, when `supportSelfIssuedProvider == true` and
no `issuerId` is configured, an id_token whose `iss` is the literal `https://self-issued.me` is
routed to `validateSelfIssuedProvider(JwtClaims, String, boolean)` — an **empty method** — skipping
the entire normal-issuer validation block (issuer-id, subject, authorized party, audience, `exp`,
`iat`, `nbf`). An id_token with `iss=https://self-issued.me` is therefore accepted with no
claims-level validation. (Signature verification is separate; the claims gap is unconditional once
the self-issued branch is taken.)

### CVSS v3.1 (recommended)
**3.7 — LOW**  `AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`

| Metric | Value | Rationale |
|--------|-------|-----------|
| Attack Vector | Network | RP callback is network-reachable |
| Attack Complexity | High | requires the RP to enable `supportSelfIssuedProvider` and (for full bypass) weak JWS verification |
| Privileges Required | None | — |
| User Interaction | Required | victim RP callback |
| Scope | Unchanged | within the RP trust domain |
| Confidentiality / Integrity | Low | claims unvalidated; worst case (with weak JWS config) authentication bypass |

> G2△: opt-in (`supportSelfIssuedProvider=true` + `issuerId` unset). Worst case (combined with
> non-required JWS) is RP authentication bypass; with JWS required, the `sub_jwk` thumbprint still
> binds the subject, limiting the claims-gap impact.

### Proof of Concept
**Source:** `validate/targets/cxf/poc_harness/src/main/java/cxfpoc/C28_SelfIssuedBypass.java` (real
CXF 3.5.7 `OidcClaimsValidator`). Run via `run_all_round3.sh`.

Steps: `OidcClaimsValidator` with `supportSelfIssuedProvider=true`, `issuerId` unset; call
`validateJwtClaims` with claims `iss=https://self-issued.me`, `sub=attacker-chosen-subject`, **no**
aud/exp/iat.

**Verbatim result:**
```
claims: iss=https://self-issued.me, sub=attacker-chosen-subject, NO aud/exp/iat/nbf
validateJwtClaims(...) accepted=true
=> C28 CONFIRMED — self-issued id_token accepted with ZERO aud/sub/exp/iat validation
   (validateSelfIssuedProvider is an empty method).
```

**Vulnerable code (`sso/oidc/.../rp/OidcClaimsValidator.java:60-62,113-114`):**
```java
if (supportSelfIssuedProvider && issuerId == null
    && issuer != null && SELF_ISSUED_ISSUER.equals(issuer)) {
    validateSelfIssuedProvider(claims, clientId, validateClaimsAlways);   // <-- empty method
} else { ...full validation block (aud/sub/exp/iat/nbf)... }
...
private void validateSelfIssuedProvider(JwtClaims claims, String clientId, boolean validateClaimsAlways) {
}
```

### Security impact
Unvalidated self-issued id_token claims at the RP; worst case (with weak JWS config) RP
authentication bypass. Bypasses OIDC Core self-issued provider validation requirements.

### Suggested fix
Implement `validateSelfIssuedProvider` (audience = client_id, `sub_jwk` thumbprint binding to
`sub`, `exp`/`iat` checks), or default `supportSelfIssuedProvider=false`.

### Workaround (pre-fix)
Do not enable `supportSelfIssuedProvider` (leave the default `false`) unless a full self-issued
validation implementation is supplied; ensure `isJwsRequired=true`.

### Novelty / prior art (G7)
No existing CXF CVE addresses the self-issued provider path. OIDC Core 1.0 §7 defines the
self-issued validation requirements this empty method skips.

---

## Appendix — Reproduction environment

- **Target jars:** `cxf-rt-rs-security-oauth2-3.5.7`, `cxf-rt-rs-security-oauth2-saml-3.5.7`,
  `cxf-rt-rs-security-sso-oidc-3.5.7`, `cxf-rt-rs-security-jose-3.5.7` (Maven Central / `~/.m2`).
- **PoC harness:** `validate/targets/cxf/poc_harness/` —
  `bash validate/targets/cxf/poc_harness/run_all_round3.sh`
  (consolidated output: `round3_harness_output.txt`).
- PoC mains: `C25_JarRequestOverride.java`, `C26_JwtBearerReplay.java`,
  `C20_C27_JwtAccessTokenValidator.java` (C27 sub-test), `C28_SelfIssuedBypass.java`. C24 is static
  (mTLS-gated) — source quoted in §A.
- **No fabricated evidence:** all output above is a verbatim capture from the real CXF 3.5.7
  artifacts.

## Appendix — References

- Apache CXF Security Advisories: https://cxf.apache.org/security-advisories.html
- Apache CXF downloads (4.2.1 / 4.1.6 / 3.6.11): https://cxf.apache.org/
- JAX-RS OAuth2 / OAuth2 Assertions: https://cxf.apache.org/docs/jax-rs-oauth2.html , https://cxf.apache.org/docs/jaxrs-oauth2-assertions.html
- RFC 7521 §2.1 / RFC 7523 (bearer-assertion one-time-use, JWT-bearer): https://datatracker.ietf.org/doc/html/rfc7523
- RFC 9101 §2.2 (JAR — sensitive params in outer request): https://datatracker.ietf.org/doc/html/rfc9101#section-2.2
- RFC 7636 (PKCE): https://datatracker.ietf.org/doc/html/rfc7636
- OpenID Connect Core 1.0 §7 (Self-Issued OP validation): https://openid.net/specs/openid-connect-core-1_0.html
- CVE-2021-22696 (request_uri SSRF — adjacent, distinct from C25): https://nvd.nist.gov/vuln/detail/cve-2021-22696
- CVE-2026-50627 (JWT aud/iss — adjacent, distinct from C27): https://nvd.nist.gov/vuln/detail/CVE-2026-50627
- CVE-2026-50631 (refresh TOCTOU — distinct from C26): https://cxf.apache.org/security-advisories.html
- Internal registry entries (full detail): `validate/targets/cxf/CVE_CANDIDATES.md` § C24–C28.
- Internal analysis report: `validate/targets/cxf/reports/20260617_090000_cxf.md`.
