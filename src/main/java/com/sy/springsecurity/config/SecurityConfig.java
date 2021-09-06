package com.sy.springsecurity.config;

import com.alibaba.fastjson.JSONException;
import com.alibaba.fastjson.JSONObject;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @ClassName SecurityConfig
 * @Description TODO
 * @Author sy
 * @Date 2021/9/6 10:58
 * @Version 1.0
 **/
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    //@Override
    //protected AuthenticationManager authenticationManager() throws Exception {
    //    return super.authenticationManager();
    //}

    /**
     * 认证管理器配置方法
     * 基本不用动， 用来配置认证管理器
     * @param auth AuthenticationManagerBuilder
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //auth.userDetailsService(userDetailsService()).passwordEncoder(passwordEncoder());
        super.configure(auth);
    }

    /**
     *  核心过滤器配置方法
     * 一般不会过多定义，常用 ignoring() 方法用来忽略 Spring Security 对静态资源的控制
     * @param web WebSecurity
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        //web.ignoring().antMatchers(
        //        //"/login.html",
        //        "/webjar/**"
        //);
    }

    /**
     * 安全过滤器链配置方法
     * 常用，可以通过它来进行自定义安全访问策略
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //表单提交
        //http.formLogin()
        //        //自定义登录页面
        //        .loginPage("/login.html")
        //        //必须和表单提交的接口一样，会去执行自定义登录逻辑
        //        .loginProcessingUrl("/login")
        //        //登录成功后跳转的页面，必须是post请求
        //        .successForwardUrl("/toMain");

        //ajax提交
        http.formLogin()
                //自定义登录页面
                .loginPage("/login.html")
                //必须和表单提交的接口一样，会去执行自定义登录逻辑
                .loginProcessingUrl("/login")
                ////配置自定义登录验证成功的处理，这里我们返回json数据
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        JSONObject returnObj = new JSONObject();
                        try {
                            returnObj.put("code", "00000");
                            returnObj.put("message", "登录成功");
                        } catch (JSONException e) {
                            e.printStackTrace();
                        }
                        httpServletResponse.setContentType("application/json;charset=utf-8");
                        httpServletResponse.getWriter().print(returnObj.toString());
                        httpServletResponse.getWriter().flush();
                    }
                })
                //登录验证失败的处理
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        JSONObject returnObj = new JSONObject();
                        try {
                            returnObj.put("code", "50000");
                            returnObj.put("message","账号或者密码有误！" );
                        } catch (JSONException e1) {
                            e1.printStackTrace();
                        }
                        httpServletResponse.setContentType("application/json;charset=utf-8");
                        httpServletResponse.getWriter().print(returnObj.toString());
                        httpServletResponse.getWriter().flush();
                    }
                });


        //授权
        http.authorizeRequests()
                //放行 login.html，不需要认证
                .antMatchers(
                        "/login.html",
                        "/webjars/**"
                ).permitAll()
                //所有请求都必须认证才能访问，必须登录
                .anyRequest().authenticated();

        //关闭csrf防护
        http.csrf().disable();
    }

    /**
     * 将 PasswordEncoder 交由 spring 管理
     * @return BCryptPasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            //1.根据用户名去数据库查询，如果不存在抛出 UsernameNotFoundException 异常
            if (!"admin".equals(username)) {
                throw new UsernameNotFoundException("用户名不存在");
            }

            //2.在数据库中查询到用户的相关信息进行整理，例如角色，权限标志，路由等
            Set<String> dbAuthsSet = new HashSet<>();
            dbAuthsSet.add("admin");
            dbAuthsSet.add("user");

            //3.将权限信息等转换为List，传入 security 的 User。
            List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(dbAuthsSet.toArray(new String[]{}));


            //比较密码（注册时已经加密过），如果匹配成功返回 UserDetails，这里就是在数据库中查询到用户的相关信息，使用用户的密码
            String password = passwordEncoder().encode("123");

            return new User(username, password,authorities);
        };

    }
}
