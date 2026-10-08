package fuzz.cxf;

import java.util.Collections;
import javax.ws.rs.core.MultivaluedMap;

import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.grants.owner.ResourceOwnerLoginHandler;

/**
 * Mock login handler for the RFC 6749 §4.3 resource-owner-password grant.
 *
 * For fuzzing purposes every non-empty credential pair succeeds, returning a
 * deterministic UserSubject("alice", "1"). This exposes the full token-issuing
 * pipeline (scope validation, convertScopeToPermissions, saveAccessToken,
 * saveRefreshToken) to the fuzzer without requiring a real user store.
 *
 * NOTE: CXF 3.5.7's ResourceOwnerLoginHandler interface signature is:
 *   UserSubject createSubject(Client client, String name, String password)
 * with an overload that takes MultivaluedMap<String,String> params as well.
 * Both overloads are implemented here so either CXF dispatch path works.
 */
public class MockResourceOwnerLoginHandler implements ResourceOwnerLoginHandler {

    @Override
    public UserSubject createSubject(org.apache.cxf.rs.security.oauth2.common.Client client,
                                     String name,
                                     String password) {
        if (name == null || name.isEmpty() || password == null || password.isEmpty()) {
            return null;
        }
        UserSubject subject = new UserSubject(name, "1");
        subject.setRoles(Collections.singletonList("user"));
        return subject;
    }
}