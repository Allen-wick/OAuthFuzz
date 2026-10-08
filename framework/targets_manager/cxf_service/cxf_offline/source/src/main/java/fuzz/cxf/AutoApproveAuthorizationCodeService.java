package fuzz.cxf;

import java.util.List;

import javax.ws.rs.core.MultivaluedMap;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.OAuthPermission;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.services.AuthorizationCodeGrantService;

/**
 * Auto-approving variant of CXF's AuthorizationCodeGrantService used for
 * programmatic (fuzzing) clients.
 *
 * Default CXF behaviour: when the user is authenticated but the requested
 * scopes are not pre-approved, startAuthorization() builds an
 * OAuthAuthorizationData object and hands it to createHtmlResponse() →
 * Response.ok(data).build(). The sample app does NOT register a text/html
 * MessageBodyWriter for that class, so JAX-RS fails the content-negotiation
 * step and the request surfaces as HTTP 500 (seen in the terminal).
 *
 * By short-circuiting canAuthorizationBeSkipped() to always return true, we
 * route every authorize() call into createGrant(), which emits a 302 to
 * redirect_uri?code=... — exactly what RFC 6749 §4.1.2 expects and what the
 * fuzzing harness's auth_code_redirect() can consume. MockAuthFilter continues
 * to supply the Principal so userSubject is non-null inside createGrant().
 */
public class AutoApproveAuthorizationCodeService extends AuthorizationCodeGrantService {

    @Override
    protected boolean canAuthorizationBeSkipped(MultivaluedMap<String, String> params,
                                                Client client,
                                                UserSubject userSubject,
                                                List<String> requestedScope,
                                                List<OAuthPermission> permissions) {
        return true;
    }
}