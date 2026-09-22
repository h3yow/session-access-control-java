package com.github.h3yow.sessionaccesscontroljava.demo;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AuthContext;
import com.github.h3yow.sessionaccesscontroljava.auth.web.SecurityInterceptor;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 演示受保护资源：
 * - /api/demo/profile 需要 profile:read（ADMIN、USER 具备）
 * - /api/demo/admin   需要 admin:read（仅 ADMIN 具备）
 */
@RestController
@RequestMapping("/api/demo")
public class DemoController {

    @GetMapping("/profile")
    public Map<String, Object> profile(HttpServletRequest request) {
        AuthContext ctx = (AuthContext) request.getAttribute(SecurityInterceptor.AUTH_CONTEXT_ATTR);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("resource", "profile");
        body.put("at", Instant.now().toString());
        body.put("username", ctx.username());
        body.put("roles", ctx.roles());
        body.put("sessionId", ctx.sessionId());
        return body;
    }

    @GetMapping("/admin")
    public Map<String, Object> admin(HttpServletRequest request) {
        AuthContext ctx = (AuthContext) request.getAttribute(SecurityInterceptor.AUTH_CONTEXT_ATTR);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("resource", "admin");
        body.put("at", Instant.now().toString());
        body.put("username", ctx.username());
        body.put("roles", ctx.roles());
        body.put("sessionId", ctx.sessionId());
        return body;
    }
}
