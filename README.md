## spring boot 简单整合 shiro

### 1、引入依赖
```xml
<!--shiro-->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.7.1</version>
</dependency>
```
本次完整的pom依赖
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.6.7</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>

    <groupId>org.example</groupId>
    <artifactId>myexample</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
    </properties>


    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>

        <!--shiro-->
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring</artifactId>
            <version>1.7.1</version>
        </dependency>

        <!--thymeleaf-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>

    </build>
</project>
```
### 2、添加shiro配置类，重写 `AuthorizingRealm`
#### 2.1、新建 `ShiroConfig` 配置类，重写 `getShiroFilterFactoryBean` 和 `getDefaultWebSecurityManager`
```java
@Configuration
public class ShiroConfig {


    @Bean(name = "shiroFilterFactoryBean")
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager securityManager) {
        System.out.println("执行了 getShiroFilterFactoryBean！！");

        ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();
        filterFactoryBean.setSecurityManager(securityManager);
        return filterFactoryBean;
    }

    @Bean(name = "securityManager")
    public DefaultWebSecurityManager getDefaultWebSecurityManager() {
        System.out.println("执行了 getDefaultWebSecurityManager！！");

        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        return defaultWebSecurityManager;
    }

}
```
#### 2.2、新建 `ShiroRealm` 继承 `AuthorizingRealm`,并重写 `doGetAuthorizationInfo` 和 `doGetAuthenticationInfo`
2.2.1 新建 `ShiroRealm`
```java
@Component
public class ShiroRealm extends AuthorizingRealm {


    /**
     * 授权方法
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("执行了 doGetAuthorizationInfo!!");

        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        // 返回用户角色
        info.setRoles(new HashSet<>());
        // 返回用户权限
        info.setStringPermissions(new HashSet<>());
        return info;
    }

    /**
     * 认证方法
     * @param token
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        System.out.println("执行了 doGetAuthenticationInfo!!");
        String principal = (String) token.getPrincipal();
        String password = new String((char[]) token.getCredentials());

        // 判断用户名和密码是否正确
        // 后续会通过数据库来认证
        if (!"admin".equals(principal) || !"123".equals(password)) {
            throw new  AuthenticationException("账号或密码错误！");
        }
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, password, this.getName());
        return info;
    }
}
```
2.2.2 修改 `ShiroConfig` 配置类的 `getDefaultWebSecurityManager`，如下：
```java
@Bean(name = "securityManager")
public DefaultWebSecurityManager getDefaultWebSecurityManager(ShiroRealm shiroRealm) {
    System.out.println("执行了 getDefaultWebSecurityManager！！");

    DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
    //     
    defaultWebSecurityManager.setRealm(shiroRealm);
    return defaultWebSecurityManager;
}
```
### 3、编写测试页面
#### 3.1、添加`thymeleaf` 模板依赖
```xml
<!--thymeleaf-->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-thymeleaf</artifactId>
</dependency>
```
#### 3.2、添加 `login.html` 和 `index.html`
> 在`resources/templates`目录下新建

3.2.1、login.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>登录</title>
</head>
<body>
<h1>登录</h1>
<hr>
<p th:text="${msg}" style="color:red;"></p>
<form th:action="@{/login}">
    <p>用户名: <input type="text" name="username"></p>
    <p>密码: <input type="text" name="password"></p>
    <p><input type="submit"></p>
</form>
</body>
</html>
```
3.2.2、index.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>index</title>
</head>
<body>
<h1>首页</h1>
<p th:text="${msg}"></p>
<a th:href="@{/logout}">退出</a>
</body>
</html>
```
#### 3.3、编写测试controller `TestController`
```java
@Controller
@RequestMapping
public class TestController {


    /**
     * 首页
     * @param model
     * @return
     */
    @RequestMapping({"/", "/index"})
    public String toIndex(Model model) {
        model.addAttribute("msg", "hello,shiro!");
        return "index";
    }


    /**
     * 跳转登录页
     * @return
     */
    @RequestMapping("/toLogin")
    public String toLogin() {
        return "login";
    }

    /**
     * 登录接口
     * @param username
     * @param password
     * @param model
     * @return
     */
    @RequestMapping("/login")
    public String login(String username, String password, Model model) {
        Subject subject = SecurityUtils.getSubject();

        // 创建 UsernamePasswordToken
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);

        try {
            subject.login(token);
        } catch (Exception e) {
            model.addAttribute("msg", e.getMessage());
            return null;
        }

        return "redirect:index";
    }

    /**
     * 退出登录
     * @return
     */
    @RequestMapping("/logout")
    public String logout() {
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        return "redirect:toLogin";
    }

}
```
#### 3.4、修改`ShiroConfig` 的 `getShiroFilterFactoryBean`
```java
@Bean(name = "shiroFilterFactoryBean")
public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager securityManager) {
    System.out.println("执行了 getShiroFilterFactoryBean！！");

    ShiroFilterFactoryBean filterFactoryBean = new ShiroFilterFactoryBean();
    filterFactoryBean.setSecurityManager(securityManager);

    /**
     * anon: 无需认证就可以访问
     * authc: 必须认证了才能访问
     * user: 必须拥有 记住我功能 才能用
     * perms: 拥有对某个资源的权限才能访问
     * role: 拥有某个角色权限才能访问
     */
    Map<String, String> map = new HashMap<>();
    // 登录操作不需要认证
    map.put("/login", "anon");
    map.put("/toLogin", "anon");
    // 默认其他的请求都要认证才能访问
    map.put("/**", "authc");

    filterFactoryBean.setFilterChainDefinitionMap(map);

    // 添加登录页地址，没有认证的默认跳转该路径
    filterFactoryBean.setLoginUrl("/toLogin");

    return filterFactoryBean;
}
```
### 4、测试
浏览器访问 `localhost:8088` ,在没有登录的情况下会默认跳转到登录页面，如下：
<img height="500" src="\img\test_001.jpg" width="1000"/>
#### 登录后
<img height="200" src="\img\test_002.jpg" width="500"/>
