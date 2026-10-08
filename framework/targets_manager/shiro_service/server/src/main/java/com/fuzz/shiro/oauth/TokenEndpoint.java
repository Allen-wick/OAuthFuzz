package com.fuzz.shiro.oauth;

import com.fuzz.shiro.model.AccessToken;
import com.fuzz.shiro.model.AuthorizationCode;
import com.fuzz.shiro.model.ClientDetails;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class TokenEndpoint extends HttpServlet {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Map<String, AccessToken> TOKENS = new ConcurrentHashMap<>();
    private static final Map<String, AccessToken> REFRESH_TOKENS = new ConcurrentHashMap<>();

    public static Map<String, AccessToken> getTokens() { return TOKENS; }
    public static Map<String, AccessToken> getRefreshTokens() { return REFRESH_TOKENS; }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String grantType = req.getParameter("grant_type");

        if ("authorization_code".equals(grantType)) {
            handleAuthorizationCode(req, resp);
        } else if ("refresh_token".equals(grantType)) {
            handleRefreshToken(req, resp);
        } else if ("client_credentials".equals(grantType)) {
            handleClientCredentials(req, resp);
        } else if ("password".equals(grantType)) {
            handlePasswordGrant(req, resp);
        } else {
            sendError(resp, 400, "unsupported_grant_type", "Grant type not supported");
        }
    }

    private void handleAuthorizationCode(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String code = req.getParameter("code");
        String redirectUri = req.getParameter("redirect_uri");
        String clientId = req.getParameter("client_id");
        String clientSecret = req.getParameter("client_secret");
        String codeVerifier = req.getParameter("code_verifier");

        AuthorizationCode authCode = AuthorizationEndpoint.getCodes().get(code);
        if (authCode == null || authCode.isExpired() || authCode.isUsed()) {
            sendError(resp, 400, "invalid_grant", "Invalid or expired authorization code");
            return;
        }

        ClientDetails client = AuthorizationEndpoint.getClients().get(clientId);
        if (client == null || !client.validateSecret(clientSecret)) {
            sendError(resp, 401, "invalid_client", "Invalid client credentials");
            return;
        }

        if (!authCode.getClientId().equals(clientId)) {
            sendError(resp, 400, "invalid_grant", "Code was not issued to this client");
            return;
        }

        if (authCode.getRedirectUri() != null && !authCode.getRedirectUri().equals(redirectUri)) {
            sendError(resp, 400, "invalid_grant", "redirect_uri mismatch");
            return;
        }

        if (authCode.getCodeChallenge() != null) {
            String method = authCode.getCodeChallengeMethod() != null ? authCode.getCodeChallengeMethod() : "plain";
            if (!AuthorizationEndpoint.validatePkce(codeVerifier, authCode.getCodeChallenge(), method)) {
                sendError(resp, 400, "invalid_grant", "PKCE verification failed");
                return;
            }
        }

        authCode.markUsed();

        String accessToken = generateToken();
        String refreshToken = generateToken();
        AccessToken token = new AccessToken(
            accessToken, refreshToken, clientId, authCode.getUsername(),
            authCode.getScopes(), 3600
        );
        TOKENS.put(accessToken, token);
        REFRESH_TOKENS.put(refreshToken, token);

        sendTokenResponse(resp, token);
    }

    private void handleRefreshToken(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String refreshToken = req.getParameter("refresh_token");
        String clientId = req.getParameter("client_id");
        String clientSecret = req.getParameter("client_secret");

        AccessToken oldToken = REFRESH_TOKENS.get(refreshToken);
        if (oldToken == null || oldToken.isExpired() || oldToken.isRevoked()) {
            sendError(resp, 400, "invalid_grant", "Invalid or expired refresh token");
            return;
        }

        if (!oldToken.getClientId().equals(clientId)) {
            sendError(resp, 400, "invalid_grant", "Refresh token was not issued to this client");
            return;
        }

        oldToken.revoke();
        TOKENS.remove(oldToken.getTokenValue());
        REFRESH_TOKENS.remove(refreshToken);

        String newAccessToken = generateToken();
        String newRefreshToken = generateToken();
        AccessToken newToken = new AccessToken(
            newAccessToken, newRefreshToken, clientId, oldToken.getUsername(),
            oldToken.getScopes(), 3600
        );
        TOKENS.put(newAccessToken, newToken);
        REFRESH_TOKENS.put(newRefreshToken, newToken);

        sendTokenResponse(resp, newToken);
    }

    private void handleClientCredentials(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String clientId = req.getParameter("client_id");
        String clientSecret = req.getParameter("client_secret");
        String scope = req.getParameter("scope");

        ClientDetails client = AuthorizationEndpoint.getClients().get(clientId);
        if (client == null || !client.validateSecret(clientSecret)) {
            sendError(resp, 401, "invalid_client", "Invalid client credentials");
            return;
        }

        Set<String> scopes = scope != null ? new HashSet<>(Arrays.asList(scope.split("\\s+"))) : Set.of();
        String accessToken = generateToken();
        AccessToken token = new AccessToken(accessToken, null, clientId, null, scopes, 3600);
        TOKENS.put(accessToken, token);

        sendTokenResponse(resp, token);
    }

    private void handlePasswordGrant(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String clientId = req.getParameter("client_id");
        String scope = req.getParameter("scope");

        ClientDetails client = AuthorizationEndpoint.getClients().get(clientId);
        if (client == null) {
            sendError(resp, 401, "invalid_client", "Invalid client");
            return;
        }

        // Simple password validation (in production, use Shiro)
        if (!isValidUser(username, password)) {
            sendError(resp, 401, "invalid_grant", "Invalid user credentials");
            return;
        }

        Set<String> scopes = scope != null ? new HashSet<>(Arrays.asList(scope.split("\\s+"))) : Set.of();
        String accessToken = generateToken();
        String refreshToken = generateToken();
        AccessToken token = new AccessToken(accessToken, refreshToken, clientId, username, scopes, 3600);
        TOKENS.put(accessToken, token);
        REFRESH_TOKENS.put(refreshToken, token);

        sendTokenResponse(resp, token);
    }

    private boolean isValidUser(String username, String password) {
        return "user1".equals(username) && "pass1".equals(password) ||
               "user2".equals(username) && "pass2".equals(password) ||
               "admin".equals(username) && "admin".equals(password) ||
               "alice".equals(username) && "alice".equals(password);
    }

    private void sendTokenResponse(HttpServletResponse resp, AccessToken token) throws IOException {
        resp.setStatus(200);
        resp.setContentType("application/json");
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"access_token\":\"").append(token.getTokenValue()).append("\",");
        sb.append("\"token_type\":\"Bearer\",");
        sb.append("\"expires_in\":").append(token.getExpiresIn()).append(",");
        if (token.getRefreshToken() != null) {
            sb.append("\"refresh_token\":\"").append(token.getRefreshToken()).append("\",");
        }
        sb.append("\"scope\":\"").append(String.join(" ", token.getScopes())).append("\"");
        sb.append("}");
        resp.getWriter().write(sb.toString());
    }

    private void sendError(HttpServletResponse resp, int status, String error, String description) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.getWriter().write("{\"error\":\"" + error + "\",\"error_description\":\"" + description + "\"}");
    }

    public static String generateToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
