---
title: 【认证与授权】Spring Security系列之初体验
date: 2020-04-07 22:12:46
tags:
	- spring security
---

> 本篇将开始Spring Security的学习，将从最简单的搭建工程到自定义配置改造的方式完成一系列的教程。所有的代码将集中在一个工程中，通过不同的module的方式区分每一个篇章，重点突出每个module的特点，关注一个方面的功能或者配置

### 什么是Spring Security

> [官方文档]: https://docs.spring.io/spring-security/site/docs/5.2.2.BUILD-SNAPSHOT/reference/htmlsingle/#community-help
>
> 上面介绍的：
>
> ”Spring Security is a powerful and highly customizable authentication and access-control framework. It is the de-facto standard for securing Spring-based applications.“
>
> “Spring Security is a framework that focuses on providing both authentication and authorization to Java applications. Like all Spring projects, the real power of Spring Security is found in how easily it can be extended to meet custom requirements”
>
> 简单点说呢，spring security是一个非常牛的认证与授权框架。在前面的篇幅中我们介绍了，既然是认证与授权框架，那么肯定具备*用户登录认证* *基于RBAC的授权访问* 等功能了?没错。

<!-- more -->

*既然这么牛批，那我们就一起来看一下牛在哪里呢？*

由于这是一个系列的学习教程，所以我将通过一个父pom的方式管理多个module，每一个module将负责一块知识点或者配置方式的案例。

![](https://i.loli.net/2020/04/07/1Nzc7hodSFfGlyT.jpg)

### 初体验

> 本模块工程名spring-security-basic

接下来我们一起来搭建一个最简单的认证工程

#### 1、pom.xml

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

    <artifactId>spring-security-basic</artifactId>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>

</project>
```

#### 2、启动配置

```java
package cn.wujiwen.security.basic;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Desc:
 *
 * @author wujw
 * @email jiwenwu@outlook.com
 * @date 2020/4/7
 */
@SpringBootApplication
public class SecurityBasicApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecurityBasicApplication.class,args);
    }
}
```

好了！？？？ 

![](https://i.loli.net/2020/04/08/RKjvXShlQYdpCMU.png)

没错，好了。我们一起来看一下吧

其实这个时候我们已经完成了一个最简单的登录认证功能了。

![](https://i.loli.net/2020/04/08/idDaBznUGKjyX9l.gif)

`spring security`在工程启动的时候默认给我们生成了一组用户，可以看到我输入的用户名是user密码是控制台的一组随机字符串。登录成功重定向到了根路径，也就是最开始输入的路径。有人会问了，那不是404嘛，没错！但我们尚未设置根路径访问的资源啊。第一次请求`localhost:8080`的时候由于系统判定未登录会跳转到登录页面`localhost:8080/login` 。你可能又会问了，这样的用户名和密码也太奇怪了吧？我们带着这个疑问一起来看一下到底发生了什么？

### 自定义用户配置

我们找到这个路径`org.springframework.boot.autoconfigure.security.SecurityProperties.User`会看到这样一段代码

```java
@ConfigurationProperties(
    prefix = "spring.security"
)
public class SecurityProperties {
    public static final int BASIC_AUTH_ORDER = 2147483642;
    public static final int IGNORED_ORDER = -2147483648;
    public static final int DEFAULT_FILTER_ORDER = -100;
    private final SecurityProperties.Filter filter = new SecurityProperties.Filter();
    private SecurityProperties.User user = new SecurityProperties.User();

    public SecurityProperties() {
    }

    public SecurityProperties.User getUser() {
        return this.user;
    }

    public SecurityProperties.Filter getFilter() {
        return this.filter;
    }

    public static class User {
        private String name = "user";
        private String password = UUID.randomUUID().toString();
        private List<String> roles = new ArrayList();
        private boolean passwordGenerated = true;
    		
        // 省略
    }
  // 省略
}
```

可以看到在读取默认配置`prefix:spring.security`时，由于我们的application.yml中什么都没有写，所以默认生成了一个user为用户名UUID为密码的用户信息。知道了这点，我们就可以自定义一个用户信息来覆盖这里的默认配置。

1、application.yml自定义用户

```yml
spring:
  security:
    user:
      name: admin
      password: admin
```

这时重新启动工程，我们就可以用新的用户进行登录了。

2、验证登录用户信息

前面我们提到了，登录成功后会重定向到根路径`localhost:8080`,为了验证登录的用户信息，我们来添加一个根路径的请求，并返回用户的信息

```java
@RestController
public class BasicController {
    @RequestMapping("/")
    public String rootPath(HttpServletRequest request){
        Principal userPrincipal = request.getUserPrincipal();
        String name = userPrincipal.getName();
        return "您好：" + name;
    }
}
```

这个时候启动工程，我们已经发现控制台没有再输出随机的字符密码来，说明我们配置的`admin`用户已经生效了。

![](https://i.loli.net/2020/04/08/cdp4NoWhLenG3iE.gif)



这样我们一个最简单的认证登录流程就完成了，是不是很简单，我们几乎没有做任何配置，只是简单的引入依赖就可以完成流程。初体验完成，后期我们还将继续了解`spring security`的更多功能并尝试从源码的教育来分析为什么是这样。

（完）

