package com.fuzz.shiro.oauth;

import com.fuzz.shiro.model.AccessToken;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

public class IntrospectEndpoint extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String tokenValue = req.getParameter("token");
        String clientId = req.getParameter("client_id");
        String clientSecret = req.getParameter("client_secret");

        if (tokenValue == null) {
            sendJson(resp, "{\"active\":false}");
            return;
        }

        AccessToken token = TokenEndpoint.getTokens().get(tokenValue);
        if (token == null) {
            sendJson(resp, "{\"active\":false}");
            return;
        }

        if (token.isExpired() || token.isRevoked()) {
            sendJson(resp, "{\"active\":false}");
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"active\":true,");
        sb.append("\"scope\":\"").append(String.join(" ", token.getScopes())).append("\",");
        sb.append("\"client_id\":\"").append(token.getClientId()).append("\",");
        if (token.getUsername() != null) {
            sb.append("\"username\":\"").append(token.getUsername()).append("\",");
            sb.append("\"sub\":\"").append(token.getUsername()).append("\",");
        }
        sb.append("\"token_type\":\"Bearer\",");
        sb.append("\"exp\":").append(System.currentTimeMillis() / 1000 + token.getExpiresIn()).append(",");
        sb.append("\"iat\":").append(System.currentTimeMillis() / 1000);
        sb.append("}");
        sendJson(resp, sb.toString());
    }

    private void sendJson(HttpServletResponse resp, String json) throws IOException {
        resp.setContentType("application/json");
        resp.getWriter().write(json);
    }
}
