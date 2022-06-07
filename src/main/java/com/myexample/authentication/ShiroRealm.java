package com.myexample.authentication;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.crazycake.shiro.RedisCacheManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.util.HashSet;

/**
 * @Author Jieyb
 * @Data 2022/6/6 16:50
 */
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
