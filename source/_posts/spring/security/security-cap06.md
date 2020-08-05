---
title: 【认证与授权】Spring Security自定义页面
date: 2020-05-07 20:49:58
tags:
	- spring security
---

>在前面的篇幅中，我们对认证和授权流程大致梳理了一遍。在这个过程中我们一直都是使用系统生成的默认页面，登录成功后也是直接调转到根路径页面。而在实际的开发过程中，我们是需要自定义登录页面的，有时还会添加各类验证机制，在登录成功后会跳转至指定页面，还会进行各种美化，甚至是前后端分离的方式。这时，就需要我们对自定义登录进行实现。

*本章节使用spring-security-custom-login*

<!-- more -->

## 一、工程准备

### 1、pom.xml

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <artifactId>security-study</artifactId>
        <groupId>cn.wujiwen.security</groupId>
        <version>0.0.1-SNAPSHOT</version>
    </parent>
    <modelVersion>4.0.0</modelVersion>
    <description>自定义登录页面</description>
    <artifactId>spring-security-custom-login</artifactId>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
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

我们引入了`thymeleaf`,也是官方推荐的做法。

### 2、application.yml

```yml
server:
  port: 8080

spring:
  security:
    user:
      name: admin
      password: admin
      roles: ADMIN
```

非常的熟悉，端口、基础用户等信息

### 3、启动类Application

```java
@SpringBootApplication
public class SecurityLoginApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecurityLoginApplication.class,args);
    }
}
```

##  二、自定义SecurityConfig

自定义`SecurityConfig`需继承`WebSecurityConfigurerAdapter`并重写相关配置即可，由于今天只涉及到自定义页面的信息，所以我们只需要重写`configure(HttpSecurity http)` 方法即可。在重写这个方法前，我们先来看一下原来这个方法是干什么的。

```java
	protected void configure(HttpSecurity http) throws Exception {
		http
            // 1 声明ExpressionUrlAuthorizationConfigurer，要求所有URL必须登录认证后才能访问
			.authorizeRequests().anyRequest().authenticated()
			.and()
            // 2 声明一个默认的FormLoginConfigurer
			.formLogin()
            .and()
            // 3 声明一个默认的HttpBasicConfigurer
			.httpBasic();
	}
```

1. 对任何请求要求用户已认证(通俗地讲，用户必须先登录才能访问任何资源);
2. 启用用户名密码表单登录认证机制;
3. 启用`Http Basic`认证机制;

下面我们就通过重写上述的方法来做到自定义登录页面等信息

```java
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests().anyRequest().authenticated()
                .and().httpBasic().and()
            	// 1
                .formLogin().loginPage("/login")
                // 2
            	.loginProcessingUrl("/loginAction")
            	// 3
                .defaultSuccessUrl("/index")
                .permitAll();
    }
}
```

我们发现其实和缺省方法中并没有太大的差别，只有三处的变化

* `loginPage()`中将指定自定义登录页面的请求路径
* `loginProcessingUrl()` 为认证的请求接口，也就是我们常说的`form`表单中的`action`。如果不指定，将采用`loginPage`中的值。
* `defaultSuccessUrl()`为认证成功后跳转的页面地址

## 三、自定义页面

在springboot中使用html页面这里就不过多赘述，一般情况下在resource下新建templates文件下，将需要的页面放到该文件下即可。我的路径为

```xml
_resource
  |_templates
	|_login.html
	|_index.html
```

### 1、login.thml

```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity3">
<head>
    <title>Spring Security Example </title>
</head>
<body>
<div th:if="${param.error}">
    用户名或密码错误
</div>
<div th:if="${param.logout}">
    你已经退出
</div>
<form th:action="@{/loginAction}" method="post">
    <div><label> 账号 : <input type="text" name="username"/> </label></div>
    <div><label> 密码 : <input type="password" name="password"/> </label></div>
    <div><input type="submit" value="登录"/></div>
</form>
</body>
</html>
```

这里我将action与loginProcessingUrl()对应，你也可以自己尝试更换或使用默认或与loginPage()一致的。

到这里我们就完成了一个最简单的表单提交的页面了。当我们点击submit按钮时，正确的请求路径将是

`curl -x POST -d "username=admin&password=admin" http://127.0.0.1:8080/loginAction`

这里可能会有个疑问了，为啥你的参数就是username和password呢？嗯～ 当然可以自己指定的啊，因为在FormLoginConfigurer中默认的指定参数

```java
public FormLoginConfigurer() {
		super(new UsernamePasswordAuthenticationFilter(), null);
		usernameParameter("username");
		passwordParameter("password");
	}
```

### 2、index.html

```html
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity3">
<head>
    <title>Spring Security Example</title>
</head>
    <body>
        <h2>Welcome <b th:text="${username}"></b></h2>
    </body>
</html>
```

这是个认证成功后的欢迎页面，比较简单，显示当前登录用户即可

## 四、BaseContoller

上面我们定义了各类路径和请求地址，接下来我们需要定义如果将这些页面映射出来

```java
@Controller
public class BaseController {
    // loginPage("/login") 将跳转到login.html
    @GetMapping("/login")
    public String login() {
        return "login";
    }
	// index.html
    @RequestMapping("/index")
    public String index(Model model, HttpServletRequest request) {
        model.addAttribute("username",request.getUserPrincipal().getName());
        return "index";
    }
}
```

## 五、测试

![](https://i.loli.net/2020/05/08/9ponZ2zawsOfiAt.gif)

到这里我们已经完成了一个简单的自定义登录页面的改造了。当然，在实际的项目中需要自定义的东西还有很多很多，比如，当认证不通过时如果操作，当用户退出登录时如果操作，这些都没有去实现。

还有人会说，这都什么年代了，前后端分离啊，这些都可以通过一步步的改造来实现的。

（完）

