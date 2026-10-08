package com.fuzz.shiro.oauth;

import com.fuzz.shiro.model.AccessToken;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;

public class RevokeEndpoint extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String tokenValue = req.getParameter("token");
        String tokenTypeHint = req.getParameter("token_type_hint");

        if (tokenValue == null) {
            resp.setStatus(400);
            return;
        }

        // Check access tokens
        AccessToken accessToken = TokenEndpoint.getTokens().get(tokenValue);
        if (accessToken != null) {
            accessToken.revoke();
            TokenEndpoint.getTokens().remove(tokenValue);
            if (accessToken.getRefreshToken() != null) {
                TokenEndpoint.getRefreshTokens().remove(accessToken.getRefreshToken());
            }
            resp.setStatus(200);
            return;
        }

        // Check refresh tokens
        AccessToken refreshLinked = TokenEndpoint.getRefreshTokens().get(tokenValue);
        if (refreshLinked != null) {
            refreshLinked.revoke();
            TokenEndpoint.getRefreshTokens().remove(tokenValue);
            TokenEndpoint.getTokens().remove(refreshLinked.getTokenValue());
            resp.setStatus(200);
            return;
        }

        // RFC 7009: invalid tokens are silently ignored
        resp.setStatus(200);
    }
}
