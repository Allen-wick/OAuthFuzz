package com.fuzz.shiro.oauth;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class LoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        resp.setContentType("text/html;charset=UTF-8");
        String error = req.getParameter("error");
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>Login</title></head><body>");
        html.append("<h1>Apache Shiro OAuth2 Login</h1>");
        if (error != null) {
            html.append("<p style='color:red'>Login failed: ").append(error).append("</p>");
        }
        html.append("<form method='POST' action='/login'>");

        // Pass through OAuth2 parameters
        String queryString = req.getQueryString();
        if (queryString != null) {
            html.append("<input type='hidden' name='oauth_params' value='")
                .append(queryString.replace("\"", "&quot;")).append("'/>");
        }

        html.append("<label>Username: <input type='text' name='username'/></label><br/>");
        html.append("<label>Password: <input type='password' name='password'/></label><br/>");
        html.append("<input type='submit' value='Login'/>");
        html.append("</form></body></html>");
        resp.getWriter().write(html.toString());
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");
        String oauthParams = req.getParameter("oauth_params");

        Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(new UsernamePasswordToken(username, password));

            // Store authenticated user in HTTP session
            req.getSession(true).setAttribute("authenticated_user", username);

            // Authentication successful — redirect back to authorize
            String authorizeUrl = "/oauth2/authorize";
            if (oauthParams != null && !oauthParams.isEmpty()) {
                authorizeUrl += "?" + oauthParams;
            }
            resp.sendRedirect(authorizeUrl);
        } catch (Exception e) {
            resp.sendRedirect("/login?error=" + URLEncoder.encode(e.getMessage(), StandardCharsets.UTF_8));
        }
    }
}
