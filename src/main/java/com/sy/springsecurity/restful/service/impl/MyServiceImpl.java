package com.sy.springsecurity.restful.service.impl;

import com.sy.springsecurity.restful.service.MyService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Collection;

/**
 * @ClassName MyServiceImpl
 * @Description TODO
 * @Author sy
 * @Date 2021/9/7 11:35
 * @Version 1.0
 **/
@Service
public class MyServiceImpl implements MyService {
    @Override
    public boolean hasPermission(HttpServletRequest request, Authentication authentication) {
        //获取到 主体
        Object obj = authentication.getPrincipal();
        //判断 主体 是否属于 UserDetails
        if (obj instanceof UserDetails) {
            //获取权限
            UserDetails userDetails = (UserDetails) obj;
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();
            //判断请求的URI是否在权限里
            return authorities.contains(new SimpleGrantedAuthority(request.getRequestURI()));
        }
        return false;
    }
}
