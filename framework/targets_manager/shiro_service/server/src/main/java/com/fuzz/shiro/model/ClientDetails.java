package com.fuzz.shiro.model;

import java.util.Set;

public class ClientDetails {
    private final String clientId;
    private final String clientSecret;
    private final Set<String> redirectUris;
    private final Set<String> scopes;
    private final Set<String> grantTypes;

    public ClientDetails(String clientId, String clientSecret, Set<String> redirectUris,
                        Set<String> scopes, Set<String> grantTypes) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUris = redirectUris;
        this.scopes = scopes;
        this.grantTypes = grantTypes;
    }

    public String getClientId() { return clientId; }
    public String getClientSecret() { return clientSecret; }
    public Set<String> getRedirectUris() { return redirectUris; }
    public Set<String> getScopes() { return scopes; }
    public Set<String> getGrantTypes() { return grantTypes; }

    public boolean validateRedirectUri(String uri) {
        return redirectUris.contains(uri);
    }

    public boolean validateSecret(String secret) {
        return clientSecret != null && clientSecret.equals(secret);
    }
}
