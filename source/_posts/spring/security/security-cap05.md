---
title: 【认证与授权】Spring Security的授权流程
date: 2020-04-16 21:54:56
tags: 
	- spring security
---

> 上一篇我们简单的分析了一下认证流程，通过程序的启动加载了各类的配置信息。接下来我们一起来看一下授权流程，争取完成和前面简单的web基于sessin的认证方式一致。由于在授权过程中，我们预先会给用于设置角色，关于如果加载配置的角色信息这里就不做介绍了，上一篇的加载过程中我们可以发现相关的信息。
>
> *本篇依旧基于spring-security-basic*

<!-- more -->

#### 配置角色信息

配置用户及其角色信息的方式很多，我们这次依旧采取配置文件的方式，不用代码或其他的配置方式，在之前的配置用户信息的地方application.yml，添加用户的角色信息。

```yml
spring:
  security:
    user:
      name: admin
      password: admin
      roles: ADMIN,USER
```

这样我们就完成了最简单的用户角色赋予。在加载用户信息时我们知道会生成一个User对象，将其用户名、密码、权限信息封装进去。

这里需要注意一下关于role信息的加载

```java
public UserBuilder roles(String... roles) {
    List<GrantedAuthority> authorities = new ArrayList<>(
        roles.length);
    for (String role : roles) {
        Assert.isTrue(!role.startsWith("ROLE_"), () -> role
                      + " cannot start with ROLE_ (it is automatically added)");
        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
    }
    return authorities(authorities);
}
```

也就是说我们上方配置的`ADMIN,USER会被转化成ROLE_ADMIN,ROLE_USER`

#### 1、获取用户信息

我们在`BasicController`类中添加一个获取认证用户信息的接口

```java
@RequestMapping("/getUser")
public String api(HttpServletRequest request) {
    // 方式一
    Principal userPrincipal = request.getUserPrincipal();
    UsernamePasswordAuthenticationToken user = ((UsernamePasswordAuthenticationToken) userPrincipal);
    System.out.println(user.toString());
	// 方式二
    SecurityContext securityContext = SecurityContextHolder.getContext();
    System.out.println(securityContext.getAuthentication());
	// 方式三
    Object context = request.getSession().getAttribute("SPRING_SECURITY_CONTEXT");
    SecurityContext securityContext1 = (SecurityContext) context;
    System.out.println(securityContext1.getAuthentication());

    return user.toString();
}
```

我们从session中去获取用户的信息，然后拿到其授权信息就可以做相应的判断了`request.getSession().getAttribute("SPRING_SECURITY_CONTEXT");`这一段代码我们找到是在`HttpSessionSecurityContextRepository.saveContext(SecurityContext context)`中放入的，`SPRING_SECURITY_CONTEXT`是其维护的常量，这样我们就有可以根据这个key去获取当前的会话信息了。

当然我们还有另外的获取用户信息的方式还记得我们在`AbstractAuthenticationProcessingFilter`这个核心过滤器中的`successfulAuthentication`方法

```java
protected void successfulAuthentication(HttpServletRequest request,
                                        HttpServletResponse response, FilterChain chain, Authentication authResult)
    throws IOException, ServletException {

    if (logger.isDebugEnabled()) {
        logger.debug("Authentication success. Updating SecurityContextHolder to contain: "
                     + authResult);
    }

    SecurityContextHolder.getContext().setAuthentication(authResult);

    rememberMeServices.loginSuccess(request, response, authResult);

    // Fire event
    if (this.eventPublisher != null) {
        eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(
            authResult, this.getClass()));
    }

    successHandler.onAuthenticationSuccess(request, response, authResult);
}
```

这里将其认证成功的结果信息放入到上下文中	`SecurityContextHolder.getContext().setAuthentication(authResult);`那我们也是可以直接通过其`get`方法获取`SecurityContextHolder.getContext();`

登陆后直接访问接口`localhost:8080/getUser`

```properties
org.springframework.security.authentication.UsernamePasswordAuthenticationToken@bade0105: Principal: org.springframework.security.core.userdetails.User@586034f: Username: admin; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_ADMIN; Credentials: [PROTECTED]; Authenticated: true; Details: org.springframework.security.web.authentication.WebAuthenticationDetails@fffbcba8: RemoteIpAddress: 0:0:0:0:0:0:0:1; SessionId: E4C77C8791C314B7B14F796B0DD38F13; Granted Authorities: ROLE_ADMIN
org.springframework.security.authentication.UsernamePasswordAuthenticationToken@bade0105: Principal: org.springframework.security.core.userdetails.User@586034f: Username: admin; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_ADMIN; Credentials: [PROTECTED]; Authenticated: true; Details: org.springframework.security.web.authentication.WebAuthenticationDetails@fffbcba8: RemoteIpAddress: 0:0:0:0:0:0:0:1; SessionId: E4C77C8791C314B7B14F796B0DD38F13; Granted Authorities: ROLE_ADMIN
org.springframework.security.authentication.UsernamePasswordAuthenticationToken@bade0105: Principal: org.springframework.security.core.userdetails.User@586034f: Username: admin; Password: [PROTECTED]; Enabled: true; AccountNonExpired: true; credentialsNonExpired: true; AccountNonLocked: true; Granted Authorities: ROLE_ADMIN; Credentials: [PROTECTED]; Authenticated: true; Details: org.springframework.security.web.authentication.WebAuthenticationDetails@fffbcba8: RemoteIpAddress: 0:0:0:0:0:0:0:1; SessionId: E4C77C8791C314B7B14F796B0DD38F13; Granted Authorities: ROLE_ADMIN
```

可以看到，控制台打印的三段信息是完全一样的。说明这里通过三种方式获取的用户信息是一致的。既然可以获取到当前登录的用户信息，接下来我们就可以通过用户信息的判断来决定其是否可以访问那些接口。

#### 2、自定义拦截器

上一步我们通过三种方式获取到了认证用户的信息，这里我们将设计一个拦截器来控制用户的访问权限。我们先设计两个接口，一个只能admin角色用户才可以访问，一个只能user角色用户才可以访问

```java
@RequestMapping("/api/admin")
public String adminApi(HttpServletRequest request){
    Principal principal = request.getUserPrincipal();
    String name = principal.getName();
    return "管理员：" + name + "你好，你可以访问/api/admin";
}

@RequestMapping("/api/user")
public String userApi(HttpServletRequest request){
    Principal principal = request.getUserPrincipal();
    String name = principal.getName();
    return "普通用户：" + name + "你好，你可以访问/api/user";
}
```

我们设计了两个接口，通过url来区别不同角色访问的结果，我们再设计一个拦截器，这里我们可以直接参考前面的文章 [基于session的认证方式](https://www.wujiwen.cn/2020/04/05/spring/security/security-cap02/) 中定义的拦截器

```java
public class AuthenticationInterceptor extends HandlerInterceptorAdapter {
    private final static String USER_SESSION_KEY = "SPRING_SECURITY_CONTEXT";
    // 前置拦截，在接口访问前处理
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Object attribute = request.getSession().getAttribute(USER_SESSION_KEY);
        if (attribute == null) {
            writeContent(response,"匿名用户不可访问");
            return false;
        } else {
            SecurityContext context = (SecurityContext) attribute;
            Collection<? extends GrantedAuthority> authorities = context.getAuthentication().getAuthorities();
            for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().equals("ROLE_ADMIN") && request.getRequestURI().contains("admin")){
                    return true;
                }
                if (authority.getAuthority().equals("ROLE_USER") && request.getRequestURI().contains("user")){
                    return true;
                }
            }
            writeContent(response,"权限不足");
            return false;
        }
    }
    //响应输出
    private void writeContent(HttpServletResponse response, String msg) throws IOException {
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json;charset=utf‐8");
        PrintWriter writer = response.getWriter();
        writer.write(msg);
    }
}
```

同时生效该拦截器

```java
@Configuration
public class WebSecurityConfig implements WebMvcConfigurer {
    // 添加自定义拦截器
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new AuthenticationInterceptor()).addPathPatterns("/api/**");
    }
}
```

#### 3、注解方式判断

通过拦截器的方式配置，看上去非常的繁琐，如果我需要给某个接口添加一个角色访问权限，还需要去修改拦截器中的判断逻辑。当然Spring Security也提供了非常方便的注解模式去控制接口，需要修改哪个接口的角色访问，直接在接口上修改就可以了

```java
@PreAuthorize("hasRole('ADMIN')")
@RequestMapping("/api2/admin")
public String admin2Api(String message){
    return "hello : " + message;
}

@PreAuthorize("hasRole('USER')")
@RequestMapping("/api2/user")
public String user2Api(String message){
    return "hello : " + message;
}
```

非常的简单，一个注解就帮我们解决了拦截器中完成的事情，其实他们的原理是差不多的。不过这里有几个需要关注的点

* @PreAuthorize注解的生效，需要提前开启的。需要在@EnableGlobalMethodSecurity(prePostEnabled = true) 注解中生效，因为PreAuthorize 默认是false

* @PreAuthorize是支持表达式方式进行设置的，我用的是hasRole。是其内置的表达式库SecurityExpressionRoot中的方法

* hasRole最终调用的是hasAnyAuthorityName的方法，这里会有一个缺省的前缀，当前你也可以写成hasRole('ROLE_ADMIN')的。并且是变长数组，我们还可一进行多角色的判断例如：hasRole('ROLE','USER')

  ```java
  private boolean hasAnyAuthorityName(String prefix, String... roles) {
      Set<String> roleSet = getAuthoritySet();
  
      for (String role : roles) {
          String defaultedRole = getRoleWithDefaultPrefix(prefix, role);
          if (roleSet.contains(defaultedRole)) {
              return true;
          }
      }
  
      return false;
  }
  ```

  

到这里，我们已经完成了基于拦截器和注解方式的接口授权设置，基本上都是在零配置的基础上完成的。我们写发现了，好像不太容易扩展信息，例如application.yml中没办法同时设置多个用户，认证成功后我想跳转到自定义的页面或者自定义的信息。别急，从下一篇开始，我们将逐步对代码进行改造，一步一步打造成你想满足的各种需求

（完）









