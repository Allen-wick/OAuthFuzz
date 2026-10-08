package fuzz.cxf;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * Injects a fake authenticated Principal ("alice") so CXF's
 * RedirectionBasedGrantService.startAuthorization() finds a non-null
 * SecurityContext.userPrincipal and creates a UserSubject for the grant.
 *
 * IMPORTANT: this wrapper MUST NOT be applied to the token / introspect /
 * revoke endpoints.  CXF's AbstractTokenService.authenticateClientIfNeeded()
 * has the following branch (verified against cxf-3.5.x-fixes source):
 *
 *     Principal principal = sc.getUserPrincipal();
 *     if (principal == null) {
 *         // form client_id + client_secret path
 *     } else {
 *         if (clientId != null && !clientId.equals(principal.getName())) {
 *             reportInvalidClient();   // 401 {"error":"invalid_client"}
 *         }
 *     }
 *
 * If MockAuthFilter injects "alice" on the /token request, CXF compares
 * "fuzz-client".equals("alice") → false, returns 401 invalid_client BEFORE
 * ever validating the form-encoded client_secret.  The same trap exists at
 * /introspect and /revoke.
 *
 * Therefore the wrapper is applied only to /authorize and /authorize/decision.
 * All other CXF OAuth endpoints reach the servlet with the unmodified request,
 * so getUserPrincipal() returns null and form-credential client auth runs.
 */
public class MockAuthFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpReq = (HttpServletRequest) request;
        if (shouldInjectPrincipal(httpReq)) {
            chain.doFilter(wrapWithPrincipal(httpReq), response);
        } else {
            chain.doFilter(request, response);
        }
    }

    /**
     * Inject the fake Principal only on the OAuth authorization endpoints.
     * Everything else (including /token, /introspect, /revoke, /jwk, /userinfo
     * and any non-CXF resource) is passed through unmodified.
     */
    private boolean shouldInjectPrincipal(HttpServletRequest req) {
        String uri = req.getRequestURI();
        if (uri == null) {
            return false;
        }
        // Match CXF's authorize routes regardless of context path.
        // RedirectionBasedGrantService publishes:
        //   GET  /authorize
        //   POST /authorize
        //   GET  /authorize/decision
        //   POST /authorize/decision
        // The webapp publishes the JAX-RS server at /services/oauth2 so the
        // full URI is e.g. /services/oauth2/authorize[/decision].
        return uri.endsWith("/authorize")
            || uri.contains("/authorize/")
            || uri.contains("/authorize?");
    }

    private HttpServletRequestWrapper wrapWithPrincipal(HttpServletRequest httpReq) {
        return new HttpServletRequestWrapper(httpReq) {
            @Override
            public Principal getUserPrincipal() {
                return new Principal() {
                    @Override
                    public String getName() {
                        return "alice";
                    }
                };
            }

            @Override
            public boolean isUserInRole(String role) {
                return true;
            }

            @Override
            public String getAuthType() {
                return "MOCK";
            }

            @Override
            public String getRemoteUser() {
                return "alice";
            }
        };
    }

    @Override
    public void destroy() {
    }
}