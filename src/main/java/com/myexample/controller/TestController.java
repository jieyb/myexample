package com.myexample.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.Arrays;
import java.util.List;

/**
 * @Author Jieyb
 * @Data 2022/6/6 17:23
 */
@Controller
@RequestMapping
public class TestController {

    public static void main(String[] args) {
        String str = "12,55";
        List<String> strings = Arrays.asList(str);
        System.out.println(strings);
    }

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
