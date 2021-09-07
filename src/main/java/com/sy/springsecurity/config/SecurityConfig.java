package com.sy.springsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;
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
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private DataSource dataSource;

    @Autowired
    private PersistentTokenRepository persistentTokenRepository;

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
        http.formLogin()
                //自定义用户名参数，必须与form中的name一样
                //.usernameParameter("username")
                //自定义密码参数，必须与form中的name一样
                //.passwordParameter("password")
                //自定义登录页面
                .loginPage("/showLogin")
                //必须和表单提交的接口一样，会去执行自定义登录逻辑
                .loginProcessingUrl("/login")
                //登录成功后跳转的页面，必须是post请求
                .successForwardUrl("/toMain")
                //自定义登录成功后的处理器，进行重定。
                //.successHandler(new MyAuthenticationSuccessHandler("/main.html"))
                //登录失败后跳转的页面，必须是post请求
                .failureForwardUrl("/toError");
                //自定义登录失败后的处理器，进行重定。
                //.failureHandler(new MyAuthenticationFailureHandler("/error.html"));

        //ajax提交
        //http.formLogin()
        //        //自定义用户名参数，必须与form中的name一样
        //        .usernameParameter("username")
        //        //自定义密码参数，必须与form中的name一样
        //        .passwordParameter("password")
        //        //自定义登录页面
        //        .loginPage("/login.html")
        //        //必须和表单提交的接口一样，会去执行自定义登录逻辑
        //        .loginProcessingUrl("/login")
        //        //自定义登录成功后的处理器，进行重定向到百度。
        //        //.successHandler(new MyAuthenticationSuccessHandler("http://www.baidu.com"))
        //        //配置自定义登录验证成功的处理，这里我们返回json数据
        //        .successHandler(new AuthenticationSuccessHandler() {
        //            @Override
        //            public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        //                JSONObject returnObj = new JSONObject();
        //                try {
        //                    returnObj.put("code", "00000");
        //                    returnObj.put("message", "登录成功");
        //                } catch (JSONException e) {
        //                    e.printStackTrace();
        //                }
        //                httpServletResponse.setContentType("application/json;charset=utf-8");
        //                httpServletResponse.getWriter().print(returnObj.toString());
        //                httpServletResponse.getWriter().flush();
        //            }
        //        })
        //        //登录验证失败的处理
        //        .failureHandler(new AuthenticationFailureHandler() {
        //            @Override
        //            public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        //                JSONObject returnObj = new JSONObject();
        //                try {
        //                    returnObj.put("code", "50000");
        //                    returnObj.put("message", "账号或者密码有误！");
        //                } catch (JSONException e1) {
        //                    e1.printStackTrace();
        //                }
        //                httpServletResponse.setContentType("application/json;charset=utf-8");
        //                httpServletResponse.getWriter().print(returnObj.toString());
        //                httpServletResponse.getWriter().flush();
        //            }
        //        });


        //授权
        http.authorizeRequests()
                //放行 login.html，不需要认证。ant表达式
                .antMatchers(
                        "/login.html",
                        "/error.html",
                        "/img/**",
                        "/webjars/**",
                        "/showLogin"
                ).permitAll()
                //必须是post请求访问demo controller 才放行
                //.antMatchers(HttpMethod.POST,"/demo").permitAll()
                //权限控制，指定权限。在自定义逻辑中设置的,严格区分大小写
                //.antMatchers("/main1.html").hasAuthority("admin")
                ////多个权限
                //.antMatchers("/main1.html").hasAnyAuthority("admin", "admiN")
                //权限控制，指定角色。在自定义逻辑中设置的,严格区分大小写
                //.antMatchers("/main1.html").hasRole("abc")
                //多个角色
                //.antMatchers("/main1.html").hasAnyRole("abc", "abC")
                //基于IP地址
                //.antMatchers("/main1.html").hasIpAddress("192.168.111.2")
                //所有请求都必须认证才能访问，必须登录，必须放在最后面。按顺序执行的
                .anyRequest().authenticated();
                //自定义 access 方法
                //.anyRequest().access("@myServiceImpl.hasPermission(request,authentication)");

        //记住我设置
        http.rememberMe()
                //设置数据源
                .tokenRepository(persistentTokenRepository)
                //超时时间
                .tokenValiditySeconds(60)
                //自定义登录逻辑
                .userDetailsService(userDetailsService());

        //退出
        http.logout()
                //自定义退出请求接口
                .logoutUrl("/logout")
                //退出成功返回的地址，和自定页面设置的一样
                .logoutSuccessUrl("/showLogin");


        //关闭csrf防护，关闭的话需要在页面发送token
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

    @Bean
    public PersistentTokenRepository persistentTokenRepository() {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        //设置数据源
        jdbcTokenRepository.setDataSource(dataSource);
        //自动建表,第一次启动开启，第二次启动注释掉
        //jdbcTokenRepository.setCreateTableOnStartup(true);
        return jdbcTokenRepository;

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
            //设置角色，必须 ROLE_ 开头，硬性要求
            dbAuthsSet.add("ROLE_abc");
            // 配合自定义access方法使用
            dbAuthsSet.add("/main.html");

            //3.将权限信息等转换为List，传入 security 的 User。
            List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(dbAuthsSet.toArray(new String[]{}));


            //比较密码（注册时已经加密过），如果匹配成功返回 UserDetails，这里就是在数据库中查询到用户的相关信息，使用用户的密码
            String password = passwordEncoder().encode("123");

            return new User(username, password,authorities);
        };

    }
}
