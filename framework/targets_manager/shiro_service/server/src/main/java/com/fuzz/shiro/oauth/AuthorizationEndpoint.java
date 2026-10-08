package com.fuzz.shiro.oauth;

import com.fuzz.shiro.model.AuthorizationCode;
import com.fuzz.shiro.model.ClientDetails;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class AuthorizationEndpoint extends HttpServlet {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, AuthorizationCode> CODES = new ConcurrentHashMap<>();
    private static final Map<String, ClientDetails> CLIENTS = new ConcurrentHashMap<>();

    static {
        // Register test clients
        CLIENTS.put("test-client", new ClientDetails(
            "test-client", "test-secret",
            Set.of("http://127.0.0.1:8080/callback", "http://localhost:8080/callback",
                   "http://127.0.0.1:8085/callback", "http://localhost:8085/callback"),
            Set.of("openid", "profile", "email", "read", "write"),
            Set.of("authorization_code", "refresh_token", "client_credentials", "password")
        ));
        CLIENTS.put("fuzz-client", new ClientDetails(
            "fuzz-client", "fuzz-secret",
            Set.of("http://127.0.0.1:7777/callback", "http://localhost:7777/callback"),
            Set.of("openid", "profile", "email", "read", "write"),
            Set.of("authorization_code", "refresh_token")
        ));
    }

    public static Map<String, AuthorizationCode> getCodes() { return CODES; }
    public static Map<String, ClientDetails> getClients() { return CLIENTS; }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String clientId = req.getParameter("client_id");
        String redirectUri = req.getParameter("redirect_uri");
        String responseType = req.getParameter("response_type");
        String scope = req.getParameter("scope");
        String state = req.getParameter("state");
        String codeChallenge = req.getParameter("code_challenge");
        String codeChallengeMethod = req.getParameter("code_challenge_method");

        ClientDetails client = CLIENTS.get(clientId);
        if (client == null) {
            sendError(resp, 400, "invalid_client", "Unknown client_id");
            return;
        }

        if (!"code".equals(responseType)) {
            sendErrorRedirect(resp, redirectUri, "unsupported_response_type", state);
            return;
        }

        if (redirectUri != null && !client.validateRedirectUri(redirectUri)) {
            sendError(resp, 400, "invalid_request", "Invalid redirect_uri");
            return;
        }

        // Check authentication from HTTP session (set by LoginServlet + filter)
        String username = (String) req.getAttribute("authenticated_user");
        if (username == null) {
            HttpSession session = req.getSession(false);
            if (session != null) {
                username = (String) session.getAttribute("authenticated_user");
            }
        }
        if (username == null) {
            // Not authenticated — redirect to login
            String loginUrl = "/login?" + req.getQueryString();
            resp.sendRedirect(loginUrl);
            return;
        }

        String code = generateCode();

        Set<String> scopes = scope != null ? new HashSet<>(Arrays.asList(scope.split("\\s+"))) : Set.of();
        AuthorizationCode authCode = new AuthorizationCode(
            code, clientId, redirectUri, username, scopes, codeChallenge, codeChallengeMethod
        );
        CODES.put(code, authCode);

        String redirect = redirectUri + "?code=" + code;
        if (state != null) {
            redirect += "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
        }
        resp.sendRedirect(redirect);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        doGet(req, resp);
    }

    private void sendError(HttpServletResponse resp, int status, String error, String description)
            throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.getWriter().write("{\"error\":\"" + error + "\",\"error_description\":\"" + description + "\"}");
    }

    private void sendErrorRedirect(HttpServletResponse resp, String redirectUri, String error, String state)
            throws IOException {
        if (redirectUri == null) {
            sendError(resp, 400, error, "");
            return;
        }
        String url = redirectUri + "?error=" + error;
        if (state != null) {
            url += "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);
        }
        resp.sendRedirect(url);
    }

    public static String generateCode() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public static boolean validatePkce(String codeVerifier, String codeChallenge, String method) {
        if (codeChallenge == null || codeVerifier == null) {
            return codeChallenge == null;
        }
        try {
            if ("S256".equals(method)) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
                String computed = Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
                return codeChallenge.equals(computed);
            } else {
                return codeChallenge.equals(codeVerifier);
            }
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }
}
