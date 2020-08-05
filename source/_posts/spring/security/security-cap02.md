---
title: 【认证与授权】2、基于session的认证方式
date: 2020-04-05 13:40:13
tags:	
	- oauth2 
	- spring security
---

这一篇将通过一个简单的`web`项目实现基于`Session`的认证授权方式，也是以往传统项目的做法。
*先来复习一下流程*

> 用户认证通过以后，在服务端生成用户相关的数据保存在当前会话`（Session）`中，发给客户端的数据将通过`session_id `存放在`cookie`中。在后续的请求操作中，客户端将带上`session_id`，服务端就可以验证是否存在了，并可拿到其中的数据校验其合法性。当用户退出系统或`session_id`到期时，服务端则会销毁`session_id`。具体可查看上篇的基本概念了解。

<!-- more -->

### 1. 创建工程

本案例为了方便，直接使用`springboot`快速创建一个`web`工程

#### pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
   <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.2.5.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <modelVersion>4.0.0</modelVersion>
    <artifactId>simple-mvc</artifactId>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
    </dependencies>
</project>
```

### 1.2 实现认证功能

实现认证功能，我们一般需要这样几个资源

* 认证的入口（认证页面）
* 认证的凭证（用户的凭证信息）
* 认证逻辑（如何才算认证成功）

*认证页面* 
也就是我们常说的登录页

```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity3">
<head>
    <title>Login</title>
</head>
<body>
<form th:action="@{/login}" method="post">
    <div><label> User Name : <input type="text" name="username"/> </label></div>
    <div><label> Password: <input type="password" name="password"/> </label></div>
    <div><input type="submit" value="登录"/></div>
</form>
</body>
</html>
```
*页面控制器*
现在有了认证页面，那我如果才可以进入到认证页面呢，同时我点击登陆后，下一步该做什么呢？
```java
@Controller
public class LoginController {
  	// 认证逻辑处理
    @Autowired
    private AuthenticationService authenticationService;
  
		// 根路径直接跳转至认证页面
    @RequestMapping("/")
    public String loginUrl() {
        return "/login";
    }

		// 认证请求
    @RequestMapping("/login")
    @ResponseBody
    public String login(HttpServletRequest request) {
   AuthenticationRequest authenticationRequest = new AuthenticationRequest(request);
        User user = authenticationService.authentication(authenticationRequest);
        return user.getUsername() + "你好！";
    }
}
```

通过客户端传递来的参数进行处理

```java
public class AuthenticationRequest {
    private String username;
    private String password;

    public AuthenticationRequest(HttpServletRequest request){
        username = request.getParameter("username");
        password = request.getParameter("password");
    }
    // 省略 setter getter
}
```

同时我们还需要一个状态用户信息的对象User

```java
public class User {
    private Integer userId;
    private String username;
    private String password;
    private boolean enable;

    public User(Integer userId, String username, String password, boolean enable) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.enable = enable;
    }
		// 省略 setter getter
}
```

有了用户了，有了入口了，接下来就是对这些数据的处理，看是否如何认证条件了

```java
@Service
public class AuthenticationService{
		// 模拟数据库中保存的两个用户
    private static final Map<String, User> userMap = new HashMap<String, User>() {{
        put("admin", new User(1, "admin", "admin", true));
        put("spring", new User(2, "spring", "spring", false));
    }};

    private User loginByUserName(String userName) {
        return userMap.get(userName);
    }

    @Override
    public User authentication(AuthenticationRequest authenticationRequest) {
        if (authenticationRequest == null
                || StringUtils.isEmpty(authenticationRequest.getUsername())
                || StringUtils.isEmpty(authenticationRequest.getPassword())) {
            throw new RuntimeException("账号或密码为空");
        }
        User user = loginByUserName(authenticationRequest.getUsername());
        if (user == null) {
            throw new RuntimeException("用户不存在");
        }
        if(!authenticationRequest.getPassword().equals(user.getPassword())){
            throw new RuntimeException("密码错误");
        }
        if (!user.isEnable()){
            throw new RuntimeException("该账户已被禁用");
        }
        return user;
    }
}
```

这里我们模拟了两个用户，一个是正常使用的账号，还有个账号因为某些特殊的原因被封禁了，我们一起来测试一下。

启动项目在客户端输入`localhost:8080` 会直接跳转到认证页面

![login1.png](https://i.loli.net/2020/04/05/QeUvAE8Ipr3XD5W.png)

我们分别尝试不同的账户密码登录看具体显示什么信息。

1、数据的密码不正确

![error1.png](https://i.loli.net/2020/04/05/au3GP5zgLIi42kp.png)

2、账户被禁用

![error2.png](https://i.loli.net/2020/04/05/JheF8dISQmxjfsz.png)

3、数据正确的用户名和密码

![success1.png](https://i.loli.net/2020/04/05/BjbwtXKDI7QN1eP.png)

此时我们的测试均已符合预期，能够将正确的信息反馈给用户。这也是最基础的认证功能，用户能够通过系统的认证，说明他是该系统的合法用户，但是用户在后续的访问过程中，我们需要知道到底是哪个用户在操作呢，这时我们就需要引入到会话的功能呢。

### 1.3 实现会话功能

[会话](https://baike.baidu.com/item/会话/1657433)是指一个终端用户与交互系统进行通讯的过程，比如从输入账户密码进入操作系统到退出操作系统就是一个会话过程。
1、增加会话的控制

*关于`session`的操作，可参考`HttpServletRqeust`的相关API*

前面引言中我们提到了session_id的概念，与客户端的交互。
定义一个常量作为存放用户信息的key，同时在登录成功后保存用户信息

```
privata finl static String USER_SESSION_KEY = "user_session_key";
@RequestMapping("/login")
@ResponseBody
public String login(HttpServletRequest request) {
	AuthenticationRequest authenticationRequest = new AuthenticationRequest(request);
	User user = authenticationService.authentication(authenticationRequest);
	request.getSession().setAttribute(USER_SESSION_KEY,user);
	return user.getUsername() + "你好！";
}
```

2、测试会话的效果

既然说用户认证后，我们将用户的信息保存在了服务端中，那我们就测试一下通过会话，服务端是否知道后续的操作是哪个用户呢？我们添加一个获取用户信息的接口` /getUser`，看是否能后查询到当前登录的用户信息

```java
@ResponseBody
@RequestMapping("/getUser")
public String getUser(HttpServletRequest request){
  Object object = request.getSession().getAttribute("user_");
  if (object != null){
    User user = (User) object;
    return "当前访问用户为：" + user.getUsername();
  }
  return "匿名用户访问";
}
```

我们通过客户端传递的信息，在服务端查询是否有用户信息，如果没有则是匿名用户的访问，如果有则返回该用户信息。

首先在不登录下直接访问`localhost:8080/getUser` 返回`匿名用户访问`

登陆后再访问返回`当前访问用户为：admin`

此时我们已经可以看到当认证通过后，后续的访问服务端通过会话机制将知道当前访问的用户是说，这将便于我们进一步处理对用户和资源的控制。

### 1.4 实现授权功能

既然我们知道了是谁在访问用户，接下来我们将对用户访问的资源进行控制。

* 匿名用户针对部分接口不可访问，提示其认证后再访问
* 根据用户拥有的权限对资源进行操作（资源查询/资源更新）

1、实现匿名用户不可访问。

前面我们已经可以通过`/getUser`的接口示例中知道是否是匿名用户，那接下来我们就对匿名用户进行拦截后跳转到认证页面。

```java
public class NoAuthenticationInterceptor extends HandlerInterceptorAdapter {
    private final static String USER_SESSION_KEY = "user_session_key";
    // 前置拦截，在接口访问前处理
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Object attribute = request.getSession().getAttribute(USER_SESSION_KEY);
        if (attribute == null){
            // 匿名访问 跳转到根路径下的login.html
            response.sendRedirect("/");
            return false;
        }
        return true;
    }
}
```

然后再将自定义的匿名用户拦截器，放入到`web`容器中使其生效

```java
@Configuration
public class WebSecurityConfig implements WebMvcConfigurer {
    // 添加自定义拦截器,保护路径/protect 下的所有接口资源
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new 	NoAuthenticationInterceptor()).addPathPatterns("/protect/**");
    }
}
```

我们保护`/protect` 下的所有接口资源，当匿名用户访问上述接口时，都将被系统跳转到认证页面进行认证后才可以访问。

```java
@ResponseBody
@RequestMapping("/protect/getResource")
public String protectResource(HttpServletRequest request){
  return "这是非匿名用户访问的资源";
}
```

这里我们就不尽兴测试页面的展示了。

2、根据用户拥有的权限对资源进行操作（资源查询/资源更新）

根据匿名用户处理的方式，我们此时也可设置拦截器，对接口的权限和用户的权限进行对比，通过后放行，不通过则提示。此时我们需要配置这样几个地方

* 用户所具有的权限
* 一个权限对比的拦截器
* 一个资源接口

改造用户信息，使其具有相应的权限

```java
public class User {
    private Integer userId;
    private String username;
    private String password;
    private boolean enable;
    // 授予权限
    private Set<String> authorities;

    public User(Integer userId, String username, String password, boolean enable,Set<String> authorities) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.enable = enable;
        this.authorities = authorities;
    }
}
```

重新设置用户

```java
private static final Map<String, User> userMap = new HashMap<String, User>() {{
  Set<String> all =new HashSet<>();
  all.add("read");
  all.add("update");
  Set<String> read = new HashSet<>();
  read.add("read");

  put("admin", new User(1, "admin", "admin", true,all));
  put("spring", new User(2, "spring", "spring", false,read));
}};
```

我们将`admin`用户设置最高权限，具有`read`和`update`操作，`spring`用户只具有`read`权限

权限拦截器

```java
public class AuthenticationInterceptor extends HandlerInterceptorAdapter {
    private final static String USER_SESSION_KEY = "user_session_key";
    // 前置拦截，在接口访问前处理
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Object attribute = request.getSession().getAttribute(USER_SESSION_KEY);
        if (attribute == null) {
            writeContent(response,"匿名用户不可访问");
            return false;
        } else {
            User user = ((User) attribute);
            String requestURI = request.getRequestURI();
            if (user.getAuthorities().contains("read") && requestURI.contains("read")) {
                return true;
            }
            if (user.getAuthorities().contains("update") && requestURI.contains("update")) {
                return true;
            }
            writeContent(response,"权限不足");
            return false;
        }
    }
    //响应输出
    private void writeContent(HttpServletResponse response, String msg) throws IOException {
        response.setContentType("text/html;charset=utf‐8"); PrintWriter writer = response.getWriter(); writer.print(msg);
        writer.close();
        response.resetBuffer();
    }
}
```

在分别设置两个操作资源的接口

```java
@ResponseBody
@RequestMapping("/protect/update")
public String protectUpdate(HttpServletRequest request){
  return "您正在更新资源信息";
}

@ResponseBody
@RequestMapping("/protect/read")
public String protectRead(HttpServletRequest request){
  return "您正在获取资源信息";
}
```

启用自定义拦截器

```java
@Configuration
public class WebSecurityConfig implements WebMvcConfigurer {
    // 添加自定义拦截器
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new NoAuthenticationInterceptor()).addPathPatterns("/protect/**");
        registry.addInterceptor(new AuthenticationInterceptor()).addPathPatterns("/protect/**");
    }
}
```

此时我们就可以使用不同的用户进行认证后访问不同的资源来进行测试了。

### 2、总结

当然，这仅仅是最简单的实践，特别是权限处理这一块，很多都是采取硬编码的方式处理，旨在梳理流程相关信息。而在正式的生产环境中，我们将会采取更安全更灵活更容易扩展的方式处理，同时也会使用非常实用的安全框架进行企业级认证授权的处理，例如`spring security`，`shiro`等安全框架，在接下来的篇幅中，我们将进入到`sping security`的学习。加油。

（完）





