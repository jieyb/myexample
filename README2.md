## Spring Boot整合Shiro，使用Redis做缓存

> 上一篇已经实现了String boot整合Shiro，这里直接开始整合Redis

### 1、引入依赖，添加配置
> 这里使用到一个 `shiro redis`
#### 1.1、添加依赖
```xml
<!--spring boot redis-->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>

<!--shiro redis-->
<dependency>
    <groupId>org.crazycake</groupId>
    <artifactId>shiro-redis</artifactId>
    <version>3.3.1</version>
    <exclusions>
        <exclusion>
            <groupId>com.ibm.icu</groupId>
            <artifactId>icu4j</artifactId>
        </exclusion>
        <exclusion>
            <groupId>net.sf.saxon</groupId>
            <artifactId>Saxon-HE</artifactId>
        </exclusion>
    </exclusions>
</dependency>
```
#### 1.2、添加连接配置
yaml 格式
```yaml
spring:
  redis:
    host: localhost
    port: 6379
    database: 0
# 如果redis设置有密码就配置
#    password: 
```
properties 格式
```properties
spring.redis.host=localhost
spring.redis.port=6379
spring.redis.database=0
# 如果redis设置有密码就配置
#spring.redis.password=
```
### 2、修改 `ShiroConfig`，添加redis配置
2.1、引入 `RedisProperties`
```java
    @Autowired
    private RedisProperties redisProperties;
```
2.2、添加配置
```java
/**
 * redis 缓存管理
 * @return
 */
@Bean
public RedisCacheManager redisCacheManager() {
    RedisCacheManager redisCacheManager = new RedisCacheManager();
    redisCacheManager.setRedisManager(redisManager());
    return redisCacheManager;
}

/**
 * RedisManager 配置
 * @return
 */
private RedisManager redisManager() {
    RedisManager redisManager = new RedisManager();
    redisManager.setHost(redisProperties.getHost() + ":" + redisProperties.getPort());

    if (redisProperties.getPassword() != null && !"".equals(redisProperties.getPassword())) {
        redisManager.setPassword(redisProperties.getPassword());
    }
    redisManager.setDatabase(redisProperties.getDatabase());
    return redisManager;
}
```
### 3、修改 `ShiroRealm`，添加开启缓存的配置
```java
@Autowired
private RedisCacheManager redisCacheManager;

/**
 * 初始化配置
 */
@PostConstruct
private void initConfig() {
    setAuthorizationCachingEnabled(true);
    // 也可以给缓存设置名称
    // setAuthorizationCacheName("");
    setAuthenticationCachingEnabled(true);
    // 也可以给缓存设置名称
    setAuthenticationCacheName("MyAuthenticationCacheName");
    setCacheManager(redisCacheManager);
}
```
### 完整的`ShiroRealm`
```java
@Component
public class ShiroRealm extends AuthorizingRealm {

    @Autowired
    private RedisCacheManager redisCacheManager;

    /**
     * 初始化配置
     */
    @PostConstruct
    private void initConfig() {
        setAuthorizationCachingEnabled(true);
        // 也可以给缓存设置名称
        // setAuthorizationCacheName("");
        setAuthenticationCachingEnabled(true);
        // 也可以给缓存设置名称
        setAuthenticationCacheName("MyAuthenticationCacheName");
        setCacheManager(redisCacheManager);
    }

    /**
     * 授权方法
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("执行了 doGetAuthorizationInfo!!");
        String username = (String) principals.getPrimaryPrincipal();
        // 查询数据库获取用户角色权限
        // User user = userService.getUserAuthorization(username);
        // Set<String> roles = user.getRoles();
        // Set<String> permissions = user.getPermissions();

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

        if (!"admin".equals(principal) || !"123".equals(password)) {
            throw new  AuthenticationException("账号或密码错误！");
        }
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal, password, this.getName());
        return info;
    }
}

```
### 完整的`ShiroConfig`
```java
@Configuration
public class ShiroConfig {

    @Autowired
    private RedisProperties redisProperties;

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

    @Bean(name = "securityManager")
    public DefaultWebSecurityManager getDefaultWebSecurityManager(ShiroRealm shiroRealm) {
        System.out.println("执行了 getDefaultWebSecurityManager！！");

        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        defaultWebSecurityManager.setRealm(shiroRealm);
        return defaultWebSecurityManager;
    }

    /**
     * （@RequiresRoles 和 @RequiresPermissions） 注解式权限控制需要配置的两个bean
     * 需要配置 DefaultAdvisorAutoProxyCreator 和 AuthorizationAttributeSourceAdvisor
     * @return
     */
    @Bean
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(@Qualifier("securityManager") DefaultWebSecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    /**
     * redis 缓存管理
     * @return
     */
    @Bean
    public RedisCacheManager redisCacheManager() {
        RedisCacheManager redisCacheManager = new RedisCacheManager();
        redisCacheManager.setRedisManager(redisManager());
        return redisCacheManager;
    }

    /**
     * RedisManager 配置
     * @return
     */
    private RedisManager redisManager() {
        RedisManager redisManager = new RedisManager();
        redisManager.setHost(redisProperties.getHost() + ":" + redisProperties.getPort());

        if (redisProperties.getPassword() != null && !"".equals(redisProperties.getPassword())) {
            redisManager.setPassword(redisProperties.getPassword());
        }
        redisManager.setDatabase(redisProperties.getDatabase());
        return redisManager;
    }

}
```
@RequiresRoles 和 @RequiresPermissions 注解的使用
```java
@RequiresPermissions({"test2:view"})
@RequestMapping("test2")
public String test2() {
    return "redirect:index";
}

@RequiresRoles({"user"})
@RequestMapping("/test")
public String test() {
    return "redirect:index";
}
```
### 4、测试
正常登录后，可以到redis中查询是否写入缓存

<img height="170" src="\img\test_003.jpg" width="800"/>