// PoC: V2 Session Linking Ignores OIDC max_age Parameter (CWE-287)
//
// Demonstrates the code path divergence between V1 and V2 OIDC auth flows:
//
// V1 (eventstore/auth_request.go):
//   checkVerificationTimeMaxAge() — 5 call sites — compares session AuthTime against MaxAuthAge
//   Logic: verificationTime.After(request.CreationDate.Add(-*request.MaxAuthAge))
//
// V2 (command/auth_request.go):
//   LinkSessionToAuthRequest() — stores MaxAge but NEVER validates it
//   The session's AuthenticationTime() is linked regardless of MaxAge
//
// Impact: A client sends max_age=1 (require auth within 1 second), but V2 links a
// stale session authenticated days ago. The auth_time in the resulting ID token
// will show the old authentication time, violating the OIDC spec §3.1.2.1.
//
// Run: go test -v -run TestMaxAgeBypass

package maxage_poc

import (
	"testing"
	"time"
)

// Recreated from internal/auth/repository/eventsourcing/eventstore/auth_request.go:1629-1637
// This is the V1 validation function — it correctly checks max_age.
func checkVerificationTimeMaxAge_V1(verificationTime time.Time, requestCreationDate time.Time, maxAuthAge *time.Duration) bool {
	if maxAuthAge == nil {
		return true // no max_age constraint
	}
	// The V1 check: session auth time must be AFTER (request creation - max_age)
	return verificationTime.After(requestCreationDate.Add(-*maxAuthAge))
}

// Simulates V2 LinkSessionToAuthRequest behavior (command/auth_request.go:87-135)
// It stores MaxAge but never validates it against the session's AuthTime.
func linkSessionToAuthRequest_V2(sessionAuthTime time.Time, sessionActive bool, maxAge *time.Duration) (accepted bool, reason string) {
	// V2 checks (from the real code):
	// 1. Auth request exists and is in Added state ✓
	// 2. Session is active ✓
	// 3. Session token is valid ✓
	// 4. Project permission check ✓
	// 5. Organization match ✓
	//
	// Missing: MaxAge validation against sessionAuthTime
	// The real code at auth_request.go:125-132 simply does:
	//   c.pushAppendAndReduce(ctx, writeModel, authrequest.NewSessionLinkedEvent(
	//     ctx, ...,
	//     sessionWriteModel.AuthenticationTime(),  // ← stored but NOT checked against MaxAge
	//     ...,
	//   ))

	if !sessionActive {
		return false, "session not active"
	}

	// V2 ACCEPTS the session regardless of how old the authentication is!
	// MaxAge is stored in writeModel.MaxAge but never compared with AuthenticationTime()
	return true, "session linked — MaxAge ignored"
}

func TestMaxAgeBypass(t *testing.T) {
	t.Log("")
	t.Log("═══════════════════════════════════════════════════════════════════")
	t.Log("PoC: V2 Session Linking Ignores OIDC max_age (Z6)")
	t.Log("V1: internal/auth/.../eventstore/auth_request.go:1629 checkVerificationTimeMaxAge")
	t.Log("V2: internal/command/auth_request.go:87 LinkSessionToAuthRequest")
	t.Log("═══════════════════════════════════════════════════════════════════")

	// Scenario: OIDC client sends max_age=30 (require auth within 30 seconds)
	maxAge30 := 30 * time.Second
	requestTime := time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)

	// ==================================================================
	// Test Case 1: Fresh session (5 seconds old) — both V1 and V2 accept
	// ==================================================================
	t.Log("")
	t.Log("── Case 1: Fresh session (5 seconds old) ──")
	freshAuthTime := requestTime.Add(-5 * time.Second)

	v1Result := checkVerificationTimeMaxAge_V1(freshAuthTime, requestTime, &maxAge30)
	v2Accepted, _ := linkSessionToAuthRequest_V2(freshAuthTime, true, &maxAge30)

	t.Logf("  Session auth time: %s", freshAuthTime.Format("15:04:05"))
	t.Logf("  Request time:      %s", requestTime.Format("15:04:05"))
	t.Logf("  max_age:           %s", maxAge30)
	t.Logf("  V1 check:          %v (correct — within max_age window)", v1Result)
	t.Logf("  V2 link:           %v", v2Accepted)
	t.Logf("  V1 == V2:          %v", v1Result == v2Accepted)

	// ==================================================================
	// Test Case 2: Stale session (1 hour old) — V1 REJECTS, V2 ACCEPTS!
	// ==================================================================
	t.Log("")
	t.Log("── Case 2: Stale session (1 hour old) — THE BUG ──")
	staleAuthTime := requestTime.Add(-1 * time.Hour)

	v1Result = checkVerificationTimeMaxAge_V1(staleAuthTime, requestTime, &maxAge30)
	v2Accepted, v2Reason := linkSessionToAuthRequest_V2(staleAuthTime, true, &maxAge30)

	t.Logf("  Session auth time: %s (1 hour before request)", staleAuthTime.Format("15:04:05"))
	t.Logf("  Request time:      %s", requestTime.Format("15:04:05"))
	t.Logf("  max_age:           %s", maxAge30)
	t.Logf("  V1 check:          %v (correctly REJECTS — session too old)", v1Result)
	t.Logf("  V2 link:           %v — %s", v2Accepted, v2Reason)

	if v1Result == v2Accepted {
		t.Fatal("V1 and V2 should DIFFER here — V1 rejects, V2 accepts")
	}
	t.Log("  ✗ BUG: V1 correctly REJECTS stale session, but V2 ACCEPTS it!")
	t.Log("    The user's 1-hour-old session bypasses max_age=30 in V2 path.")

	// ==================================================================
	// Test Case 3: Very stale session (7 days old) — V2 still accepts!
	// ==================================================================
	t.Log("")
	t.Log("── Case 3: Very stale session (7 days old) ──")
	veryStaleAuthTime := requestTime.Add(-7 * 24 * time.Hour)

	v1Result = checkVerificationTimeMaxAge_V1(veryStaleAuthTime, requestTime, &maxAge30)
	v2Accepted, _ = linkSessionToAuthRequest_V2(veryStaleAuthTime, true, &maxAge30)

	t.Logf("  Session auth time: %s (7 days before)", veryStaleAuthTime.Format("Jan 02 15:04:05"))
	t.Logf("  max_age:           %s", maxAge30)
	t.Logf("  V1 check:          %v (correctly REJECTS)", v1Result)
	t.Logf("  V2 link:           %v (WRONG — 7-day-old session accepted!)", v2Accepted)
	t.Log("  ✗ A 7-day-old session with max_age=30 is ACCEPTED by V2.")

	// ==================================================================
	// Test Case 4: max_age=1 (extreme) — V2 still accepts stale session!
	// ==================================================================
	t.Log("")
	t.Log("── Case 4: max_age=1 second (extreme) ──")
	maxAge1 := 1 * time.Second
	stale10min := requestTime.Add(-10 * time.Minute)

	v1Result = checkVerificationTimeMaxAge_V1(stale10min, requestTime, &maxAge1)
	v2Accepted, _ = linkSessionToAuthRequest_V2(stale10min, true, &maxAge1)

	t.Logf("  Session auth time: %s (10 minutes before)", stale10min.Format("15:04:05"))
	t.Logf("  max_age:           %s", maxAge1)
	t.Logf("  V1 check:          %v (correctly REJECTS)", v1Result)
	t.Logf("  V2 link:           %v (WRONG — 10-min-old session with max_age=1!)", v2Accepted)
	t.Log("  ✗ Client required re-auth within 1 second, V2 ignores it entirely.")

	// ==================================================================
	// Test Case 5: max_age=nil (not set) — both accept (correct behavior)
	// ==================================================================
	t.Log("")
	t.Log("── Case 5: max_age=nil (not specified) — correct behavior ──")
	v1Result = checkVerificationTimeMaxAge_V1(staleAuthTime, requestTime, nil)
	v2Accepted, _ = linkSessionToAuthRequest_V2(staleAuthTime, true, nil)
	t.Logf("  V1: %v, V2: %v (both accept — correct, no max_age constraint)", v1Result, v2Accepted)

	// ==================================================================
	// SUMMARY
	// ==================================================================
	t.Log("")
	t.Log("═══════════════════════════════════════════════════════════════════")
	t.Log("VERDICT:")
	t.Log("  V1 (checkVerificationTimeMaxAge):")
	t.Log("    5 call sites in eventstore/auth_request.go (lines 1318-1439)")
	t.Log("    Correctly enforces max_age by comparing session AuthTime")
	t.Log("    against request.CreationDate.Add(-MaxAuthAge)")
	t.Log("")
	t.Log("  V2 (LinkSessionToAuthRequest):")
	t.Log("    command/auth_request.go:87-135")
	t.Log("    Stores MaxAge in writeModel.MaxAge (line 68)")
	t.Log("    Records AuthenticationTime() in SessionLinkedEvent (line 129)")
	t.Log("    But NEVER compares MaxAge against AuthenticationTime()")
	t.Log("    The compliance checker at token issuance also skips max_age")
	t.Log("")
	t.Log("IMPACT:")
	t.Log("  OIDC spec §3.1.2.1: max_age specifies max elapsed seconds since")
	t.Log("  last authentication. V2 ignores this — a client requesting")
	t.Log("  max_age=1 (force re-auth) gets tokens with auth_time from days ago.")
	t.Log("  This violates OIDC Core 1.0 and enables session fixation scenarios.")
	t.Log("")
	t.Log("FIX: In LinkSessionToAuthRequest, after sessionWriteModel.CheckIsActive(),")
	t.Log("  add: if writeModel.MaxAge != nil {")
	t.Log("    authTime := sessionWriteModel.AuthenticationTime()")
	t.Log("    if !authTime.After(writeModel.CreationDate.Add(-*writeModel.MaxAge)) {")
	t.Log("      return nil, nil, zerrors.Throw...(\"session auth too old for max_age\")")
	t.Log("    }")
	t.Log("  }")
	t.Log("═══════════════════════════════════════════════════════════════════")
}
