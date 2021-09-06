# 自定义登录逻辑
## UserDetailsService
这个是 **security** 默认的登录逻辑，根据传入的用户名、密码做匹配，密码实际是传入到了构造方法中
## PasswordEncoder
用于密码加密与匹配，主要使用的实现方法是 **BCryptPasswordEncoder** 加密
当我们自定义登录逻辑的时候容器内必须有 **PasswordEncoder** 实例，也就是说要在配置类中配置她由 **spring** 去管理

# 自定义登录页面
**security** 有自己的默认登录页面，我们要修改的话只需要在配置类中进行配置即可