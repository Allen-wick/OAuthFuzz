# Ory Hydra — Authorization-Code Exchange Skips Live Scope Re-Validation (sanitized)

Internal tracking ID: C22. Status: vendor-acknowledged; under coordinated
disclosure.

At the OAuth 2.0 token endpoint, the authorization-code exchange path issues
the access token without re-validating the granted scope against the scope
consented for the session at the authorization step. The token issued at
exchange can therefore carry a scope that exceeds the scope currently
authorized. The behavior was confirmed with a live proof of concept against a
locally deployed instance.

The finding was reported to the vendor and acknowledged. Until the coordinated
disclosure process concludes, this repository intentionally omits the
reproduction details (request sequences, parameter shapes, and preconditions).
