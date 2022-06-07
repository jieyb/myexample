package com.myexample.authentication;

import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author Jieyb
 * @Data 2022/6/6 16:02
 */
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
