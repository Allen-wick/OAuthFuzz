package com.fuzz.shiro.security;

import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

import java.util.*;

public class OAuthRealm extends AuthorizingRealm {
    private final Map<String, String> users = new HashMap<>();

    public OAuthRealm() {
        // Hard-coded test users (configurable via properties in production)
        users.put("user1", "pass1");
        users.put("user2", "pass2");
        users.put("admin", "admin");
        users.put("alice", "alice");
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token)
            throws AuthenticationException {
        UsernamePasswordToken upToken = (UsernamePasswordToken) token;
        String username = upToken.getUsername();
        String password = users.get(username);

        if (password == null) {
            throw new UnknownAccountException("User not found: " + username);
        }

        if (!password.equals(new String(upToken.getPassword()))) {
            throw new IncorrectCredentialsException("Invalid password for user: " + username);
        }

        return new SimpleAuthenticationInfo(username, password.toCharArray(), getName());
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        String username = (String) principals.getPrimaryPrincipal();
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addRole("user");
        info.addStringPermission("read");
        info.addStringPermission("write");
        if ("admin".equals(username)) {
            info.addRole("admin");
            info.addStringPermission("*");
        }
        return info;
    }
}
