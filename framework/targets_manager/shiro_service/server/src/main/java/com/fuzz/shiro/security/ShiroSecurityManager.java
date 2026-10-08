package com.fuzz.shiro.security;

import org.apache.shiro.web.env.IniWebEnvironment;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.SecurityUtils;

public class ShiroSecurityManager {
    private static SecurityManager securityManager;

    public static synchronized SecurityManager init() {
        if (securityManager == null) {
            OAuthRealm realm = new OAuthRealm();
            DefaultWebSecurityManager sm = new DefaultWebSecurityManager();
            sm.setRealm(realm);
            SecurityUtils.setSecurityManager(sm);
            securityManager = sm;
        }
        return securityManager;
    }

    public static SecurityManager getInstance() {
        if (securityManager == null) {
            return init();
        }
        return securityManager;
    }
}
