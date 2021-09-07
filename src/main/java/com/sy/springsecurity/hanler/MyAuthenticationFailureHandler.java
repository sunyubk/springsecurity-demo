package com.sy.springsecurity.hanler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @ClassName MyAuthenticationFailureHandler
 * @Description TODO
 * @Author sy
 * @Date 2021/9/7 10:32
 * @Version 1.0
 **/
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    String url;

    public MyAuthenticationFailureHandler(String url) {
        this.url = url;
    }


    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        //重定向到url，源码中是转发
        httpServletResponse.sendRedirect(url);
    }
}
