package com.fuzz.shiro.oauth;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * OIDC Discovery endpoint — /.well-known/openid-configuration
 */
public class DiscoveryEndpoint extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String baseUrl = req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort();

        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"issuer\":\"").append(baseUrl).append("\",");
        sb.append("\"authorization_endpoint\":\"").append(baseUrl).append("/oauth2/authorize\",");
        sb.append("\"token_endpoint\":\"").append(baseUrl).append("/oauth2/token\",");
        sb.append("\"userinfo_endpoint\":\"").append(baseUrl).append("/oauth2/userinfo\",");
        sb.append("\"introspection_endpoint\":\"").append(baseUrl).append("/oauth2/introspect\",");
        sb.append("\"revocation_endpoint\":\"").append(baseUrl).append("/oauth2/revoke\",");
        sb.append("\"jwks_uri\":\"").append(baseUrl).append("/oauth2/jwks\",");
        sb.append("\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"read\",\"write\"],");
        sb.append("\"response_types_supported\":[\"code\"],");
        sb.append("\"grant_types_supported\":[\"authorization_code\",\"refresh_token\",\"client_credentials\",\"password\"],");
        sb.append("\"token_endpoint_auth_methods_supported\":[\"client_secret_post\",\"client_secret_basic\"],");
        sb.append("\"code_challenge_methods_supported\":[\"plain\",\"S256\"]");
        sb.append("}");
        resp.getWriter().write(sb.toString());
    }
}
