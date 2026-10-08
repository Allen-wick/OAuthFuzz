package com.fuzz.shiro.oauth;

import com.fuzz.shiro.model.AccessToken;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

public class UserInfoEndpoint extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String authHeader = req.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            resp.setStatus(401);
            resp.setHeader("WWW-Authenticate", "Bearer");
            return;
        }

        String tokenValue = authHeader.substring(7);
        AccessToken token = TokenEndpoint.getTokens().get(tokenValue);
        if (token == null || token.isExpired() || token.isRevoked()) {
            resp.setStatus(401);
            resp.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            return;
        }

        String username = token.getUsername();
        resp.setContentType("application/json");
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"sub\":\"").append(username != null ? username : token.getClientId()).append("\",");
        if (username != null) {
            sb.append("\"name\":\"").append(username).append("\",");
            sb.append("\"preferred_username\":\"").append(username).append("\",");
            sb.append("\"email\":\"").append(username).append("@example.com\",");
        }
        sb.append("\"email_verified\":true,");
        sb.append("\"scope\":\"").append(String.join(" ", token.getScopes())).append("\"");
        sb.append("}");
        resp.getWriter().write(sb.toString());
    }
}
