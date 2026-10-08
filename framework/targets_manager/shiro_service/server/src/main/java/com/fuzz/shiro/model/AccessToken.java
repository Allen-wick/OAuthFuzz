package com.fuzz.shiro.model;

import java.time.Instant;
import java.util.Set;

public class AccessToken {
    private final String tokenValue;
    private final String refreshToken;
    private final String clientId;
    private final String username;
    private final Set<String> scopes;
    private final Instant expiresAt;
    private boolean revoked;

    public AccessToken(String tokenValue, String refreshToken, String clientId, String username,
                       Set<String> scopes, long expiresIn) {
        this.tokenValue = tokenValue;
        this.refreshToken = refreshToken;
        this.clientId = clientId;
        this.username = username;
        this.scopes = scopes;
        this.expiresAt = Instant.now().plusSeconds(expiresIn);
        this.revoked = false;
    }

    public String getTokenValue() { return tokenValue; }
    public String getRefreshToken() { return refreshToken; }
    public String getClientId() { return clientId; }
    public String getUsername() { return username; }
    public Set<String> getScopes() { return scopes; }
    public long getExpiresIn() { return expiresAt.getEpochSecond() - Instant.now().getEpochSecond(); }
    public boolean isExpired() { return Instant.now().isAfter(expiresAt); }
    public boolean isRevoked() { return revoked; }
    public void revoke() { this.revoked = true; }
}
