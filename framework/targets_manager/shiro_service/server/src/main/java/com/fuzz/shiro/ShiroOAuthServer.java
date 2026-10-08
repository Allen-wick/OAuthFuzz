package com.fuzz.shiro;

import com.fuzz.shiro.oauth.*;
import com.fuzz.shiro.security.ShiroSecurityManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.util.EnumSet;

public class ShiroOAuthServer {

    public static void main(String[] args) throws Exception {
        int port = 8080;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port, using default 8080");
            }
        }

        // Initialize Shiro
        WebSecurityManager securityManager = (WebSecurityManager) ShiroSecurityManager.init();
        System.out.println("[Shiro] SecurityManager initialized");

        Server server = new Server(port);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        // Register OAuth2 endpoints
        context.addServlet(new ServletHolder(new AuthorizationEndpoint()), "/oauth2/authorize");
        context.addServlet(new ServletHolder(new TokenEndpoint()), "/oauth2/token");
        context.addServlet(new ServletHolder(new UserInfoEndpoint()), "/oauth2/userinfo");
        context.addServlet(new ServletHolder(new IntrospectEndpoint()), "/oauth2/introspect");
        context.addServlet(new ServletHolder(new RevokeEndpoint()), "/oauth2/revoke");
        context.addServlet(new ServletHolder(new DiscoveryEndpoint()), "/.well-known/openid-configuration");

        // Register login servlet
        context.addServlet(new ServletHolder(new LoginServlet()), "/login");

        // Health check
        context.addServlet(new ServletHolder(new HealthServlet()), "/health");

        // Add session-based auth filter
        context.addFilter(new FilterHolder(new OAuthSessionFilter()), "/*",
                EnumSet.of(DispatcherType.REQUEST));

        server.setHandler(context);

        System.out.println("[Shiro OAuth2 Server] Starting on port " + port);
        server.start();
        System.out.println("[Shiro OAuth2 Server] Running on http://0.0.0.0:" + port);
        server.join();
    }

    /**
     * Simple session-based filter that tracks authentication state
     * via HTTP session attributes. Shiro is used only for credential
     * validation (subject.login), not for session management.
     */
    static class OAuthSessionFilter implements Filter {

        @Override
        public void init(FilterConfig filterConfig) {}

        @Override
        public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
                throws IOException, ServletException {
            HttpServletRequest httpReq = (HttpServletRequest) request;
            HttpServletResponse httpResp = (HttpServletResponse) response;
            String path = httpReq.getRequestURI();

            // Public endpoints — pass through
            if (path.startsWith("/oauth2/token") || path.startsWith("/oauth2/introspect")
                    || path.startsWith("/oauth2/revoke") || path.startsWith("/health")
                    || path.startsWith("/.well-known/") || path.startsWith("/login")) {
                chain.doFilter(request, response);
                return;
            }

            // /oauth2/authorize — require authentication via HTTP session
            if (path.startsWith("/oauth2/authorize")) {
                HttpSession session = httpReq.getSession(false);
                if (session == null || session.getAttribute("authenticated_user") == null) {
                    String query = httpReq.getQueryString();
                    String loginUrl = "/login" + (query != null ? "?" + query : "");
                    httpResp.sendRedirect(loginUrl);
                    return;
                }
                // Make authenticated user available to downstream servlets
                httpReq.setAttribute("authenticated_user", session.getAttribute("authenticated_user"));
            }

            chain.doFilter(request, response);
        }

        @Override
        public void destroy() {}
    }

    /**
     * Health check endpoint.
     */
    static class HealthServlet extends javax.servlet.http.HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            resp.setContentType("application/json");
            resp.setStatus(200);
            resp.getWriter().write("{\"status\":\"UP\",\"server\":\"shiro-oauth-2.2.0\"}");
        }
    }
}
