# Disclosure evidence index

Verbatim evidence for findings that are fixed or carry public identifiers.
Identifiers such as C24–C28 are our internal registry numbers under which the
evidence was collected. The item still under coordinated disclosure is
represented by a sanitized description only.

## keycloak/

- `keycloak_poc_report.json` — machine-readable PoC run summary (probes against
  a locally deployed Keycloak instance)
- `keycloak_poc_logs.txt` — verbatim container and request/response logs of the
  PoC run
- `20260602_120000_keycloak.md`, `20260611_032110_keycloak.md` — per-pass
  analysis reports

## cxf/

- `cxf_poc_evidence.log` — verbatim PoC evidence
- `cxf_validation_results.json` — validation run results
- `CXF_C24-C28_CVE_Submission.md` — writeup submitted to the Apache CXF
  security team (CVE-2026-50630 / CVE-2026-50628 / CVE-2026-50629)

## authelia/

- `gen_config.py`, `start_container.sh`, `lib.py`, `authz_matrix.py` — PoC
  environment scripts
- `authz_matrix.txt` — verbatim authorization-matrix run output
- `authelia_poc_evidence.log`, `authelia_validation_results.json` — verbatim
  PoC evidence and validation results

## zitadel/

- `max_age_bypass_poc_test.go`, `poc_max_age_bypass_results.log` — proof of
  concept and verbatim test output for the missing `max_age` validation in the
  v2 session-linking path (vendor-confirmed and fixed)

## hydra/

- `HYDRA_C22_sanitized_description.md` — sanitized description of the finding
  still under coordinated disclosure (no reproduction details)
