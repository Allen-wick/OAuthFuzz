package com.fuzz.shiro.model;

import java.time.Instant;
import java.util.Set;

public class AuthorizationCode {
    private final String code;
    private final String clientId;
    private final String redirectUri;
    private final String username;
    private final Set<String> scopes;
    private final String codeChallenge;
    private final String codeChallengeMethod;
    private final Instant expiresAt;
    private boolean used;

    public AuthorizationCode(String code, String clientId, String redirectUri, String username,
                            Set<String> scopes, String codeChallenge, String codeChallengeMethod) {
        this.code = code;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.username = username;
        this.scopes = scopes;
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.expiresAt = Instant.now().plusSeconds(300); // 5 minutes
        this.used = false;
    }

    public String getCode() { return code; }
    public String getClientId() { return clientId; }
    public String getRedirectUri() { return redirectUri; }
    public String getUsername() { return username; }
    public Set<String> getScopes() { return scopes; }
    public String getCodeChallenge() { return codeChallenge; }
    public String getCodeChallengeMethod() { return codeChallengeMethod; }
    public boolean isExpired() { return Instant.now().isAfter(expiresAt); }
    public boolean isUsed() { return used; }
    public void markUsed() { this.used = true; }
}
