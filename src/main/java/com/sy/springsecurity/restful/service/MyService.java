package com.sy.springsecurity.restful.service;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * @ClassName MyService
 * @Description TODO
 * @Author sy
 * @Date 2021/9/7 11:33
 * @Version 1.0
 **/
public interface MyService {

    boolean hasPermission(HttpServletRequest request, Authentication authentication);
}
