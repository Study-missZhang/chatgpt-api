package com.zky.chatgpt.domain.security.model.vo;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * @author: ZhangKaiYuan
 * @description: Token 信息
 * @create: 2025/3/24
 */
public class JwtToken implements AuthenticationToken {
    private String jwt;

    public JwtToken(String jwt) {
        this.jwt = jwt;
    }

    /**
     * 等同于账户
     */
    @Override
    public Object getPrincipal() {
        return jwt;
    }

    /**
     * 等同于密码
     */
    @Override
    public Object getCredentials() {
        return jwt;
    }
}
