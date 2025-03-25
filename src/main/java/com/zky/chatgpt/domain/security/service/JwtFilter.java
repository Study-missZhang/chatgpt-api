package com.zky.chatgpt.domain.security.service;

import com.zky.chatgpt.domain.security.model.vo.JwtToken;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.web.filter.AccessControlFilter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author: ZhangKaiYuan
 * @description: 自定义Filter，用于拦截携带Token的请求
 * @create: 2025/3/24
 */
@Slf4j
public class JwtFilter extends AccessControlFilter {
    /**
     * isAccessAllowed 判断是否携带有效的 JwtToken
     * 所以这里直接返回一个 false，让它走 onAccessDenied 方法流程
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest servletRequest, ServletResponse servletResponse, Object o) throws Exception {
        return false;
    }


    /**
     * 返回结果为true表明登录通过
     */
    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        // 如果你设定的 token 放到 header 中，则可以这样获取；request.getHeader("Authorization");
        JwtToken jwtToken = new JwtToken(request.getParameter("token"));
        try {
            // 鉴权认证
            getSubject(servletRequest, servletResponse).login(jwtToken);
            return true;
        } catch (Exception e) {
            log.error("鉴权认证失败", e);
            onLoginFail(servletResponse);
            return false;
        }
    }

    /**
     * 鉴权认证失败时默认返回 401 状态码
     */
    private void onLoginFail(ServletResponse response) throws IOException {
        HttpServletResponse httpResponse = (HttpServletResponse) response;
        httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        httpResponse.getWriter().write("Auth Err!");
    }
}
