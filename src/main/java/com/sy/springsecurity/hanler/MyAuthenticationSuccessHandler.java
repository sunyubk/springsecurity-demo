package com.sy.springsecurity.hanler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @ClassName MyAuthenticationSuccessHandler
 * @Description TODO
 * @Author sy
 * @Date 2021/9/7 10:19
 * @Version 1.0
 **/
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    String url;

    public MyAuthenticationSuccessHandler(String url) {
        this.url = url;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        //重定向到url，源码中是转发
        httpServletResponse.sendRedirect(url);
    }
}
