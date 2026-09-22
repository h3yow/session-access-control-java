package com.github.h3yow.sessionaccesscontroljava.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 拦截器注册：仅对 /api/** 生效，其中 /api/auth/** 为公开认证端点。
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AuthorizationInterceptor authorizationInterceptor;

    public WebConfig(AuthorizationInterceptor authorizationInterceptor) {
        this.authorizationInterceptor = authorizationInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authorizationInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns("/api/auth/**");
    }
}
