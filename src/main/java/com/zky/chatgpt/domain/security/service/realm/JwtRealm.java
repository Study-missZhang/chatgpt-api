package com.zky.chatgpt.domain.security.service.realm;

import com.zky.chatgpt.domain.security.model.vo.JwtToken;
import com.zky.chatgpt.domain.security.service.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * @author: ZhangKaiYuan
 * @description: 自定义Realm
 * @create: 2025/3/24
 */
@Slf4j
public class JwtRealm extends AuthorizingRealm {

    private static JwtUtil jwtUtil = new JwtUtil();

    //判断传入的 AuthenticationToken 是否是我们需要的类型（JwtToken）
    @Override
    public boolean supports(AuthenticationToken token) {
        return token instanceof JwtToken;
    }

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        String jwt = (String) token.getPrincipal();
        if(jwt == null){
            throw new NullPointerException("jwtToken 不允许为空");
        }

        //判断jwt是否被篡改
        if(!jwtUtil.isVerify(jwt)){
            throw new UnknownAccountException();
        }

        //获取username信息，并作处理
        String username = (String) jwtUtil.decode(jwt).get("username");
        log.info("鉴权用户 username:{}", username);
        return new SimpleAuthenticationInfo(jwt, jwt, "JwtRealm");
    }
}
