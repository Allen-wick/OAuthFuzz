package fuzz.cxf;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.cxf.rs.security.oauth2.common.Client;
import org.apache.cxf.rs.security.oauth2.common.ServerAccessToken;
import org.apache.cxf.rs.security.oauth2.common.UserSubject;
import org.apache.cxf.rs.security.oauth2.grants.code.AbstractCodeDataProvider;
import org.apache.cxf.rs.security.oauth2.grants.code.ServerAuthorizationCodeGrant;
import org.apache.cxf.rs.security.oauth2.provider.OAuthServiceException;
import org.apache.cxf.rs.security.oauth2.tokens.refresh.RefreshToken;

public class InMemoryOAuthDataProvider extends AbstractCodeDataProvider {

    private final Map<String, Client> clients = new ConcurrentHashMap<>();
    private final Map<String, ServerAccessToken> accessTokens = new ConcurrentHashMap<>();
    private final Map<String, RefreshToken> refreshTokens = new ConcurrentHashMap<>();
    private final Map<String, ServerAuthorizationCodeGrant> codeGrants = new ConcurrentHashMap<>();

    public InMemoryOAuthDataProvider() {
        Client c = new Client(
            "fuzz-client", "fuzz-client-secret", true);
        c.setRedirectUris(Collections.singletonList(
            "http://127.0.0.1:7777/callback"));
        c.setAllowedGrantTypes(Arrays.asList(
            "authorization_code", "refresh_token",
            "password", "client_credentials",
            "urn:ietf:params:oauth:grant-type:jwt-bearer"));
        c.setRegisteredScopes(Arrays.asList(
            "openid", "read_resource", "write_resource"));
        setClient(c);

        Map<String, String> scopes = new LinkedHashMap<>();
        scopes.put("openid",         "OpenID Connect");
        scopes.put("read_resource",  "Read protected resource");
        scopes.put("write_resource", "Write protected resource");
        setSupportedScopes(scopes);
    }

    // ── Client management ────────────────────────────────────────

    @Override
    public Client doGetClient(String clientId) {
        return clients.get(clientId);
    }

    @Override
    public void setClient(Client client) {
        clients.put(client.getClientId(), client);
    }

    @Override
    protected void doRemoveClient(Client c) {
        clients.remove(c.getClientId());
    }

    @Override
    public List<Client> getClients(UserSubject resourceOwner) {
        List<Client> result = new ArrayList<>();
        for (Client client : clients.values()) {
            if (isClientMatched(client, resourceOwner)) {
                result.add(client);
            }
        }
        return result;
    }

    // ── Access Token management ──────────────────────────────────

    @Override
    public ServerAccessToken getAccessToken(String accessTokenKey) {
        return accessTokens.get(accessTokenKey);
    }

    @Override
    public List<ServerAccessToken> getAccessTokens(Client c, UserSubject sub) {
        List<ServerAccessToken> result = new ArrayList<>();
        for (ServerAccessToken at : accessTokens.values()) {
            if (isTokenMatched(at, c, sub)) {
                result.add(at);
            }
        }
        return result;
    }

    @Override
    protected void saveAccessToken(ServerAccessToken serverToken) {
        accessTokens.put(serverToken.getTokenKey(), serverToken);
    }

    @Override
    protected void doRevokeAccessToken(ServerAccessToken at) {
        accessTokens.remove(at.getTokenKey());
    }

    // ── Refresh Token management ─────────────────────────────────

    @Override
    protected RefreshToken getRefreshToken(String refreshTokenKey) {
        return refreshTokens.get(refreshTokenKey);
    }

    @Override
    public List<RefreshToken> getRefreshTokens(Client c, UserSubject sub) {
        List<RefreshToken> result = new ArrayList<>();
        for (RefreshToken rt : refreshTokens.values()) {
            if (isTokenMatched(rt, c, sub)) {
                result.add(rt);
            }
        }
        return result;
    }

    @Override
    protected void saveRefreshToken(RefreshToken refreshToken) {
        refreshTokens.put(refreshToken.getTokenKey(), refreshToken);
    }

    @Override
    protected void doRevokeRefreshToken(RefreshToken rt) {
        refreshTokens.remove(rt.getTokenKey());
    }

    // ── Authorization Code Grant management ──────────────────────

    @Override
    protected void saveCodeGrant(ServerAuthorizationCodeGrant grant) {
        codeGrants.put(grant.getCode(), grant);
    }

    @Override
    public ServerAuthorizationCodeGrant removeCodeGrant(String code) {
        return codeGrants.remove(code);
    }

    @Override
    public List<ServerAuthorizationCodeGrant> getCodeGrants(
            Client c, UserSubject sub) {
        List<ServerAuthorizationCodeGrant> result = new ArrayList<>();
        for (ServerAuthorizationCodeGrant grant : codeGrants.values()) {
            if (isCodeMatched(grant, c, sub)) {
                result.add(grant);
            }
        }
        return result;
    }
}