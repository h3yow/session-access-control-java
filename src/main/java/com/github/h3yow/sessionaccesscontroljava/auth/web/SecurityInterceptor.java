package com.github.h3yow.sessionaccesscontroljava.auth.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.sessionaccesscontroljava.auth.model.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.auth.model.AuthContext;
import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;
import com.github.h3yow.sessionaccesscontroljava.auth.security.AccessGuard;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 安全拦截器：按“路径 -> 所需权限”策略执行访问控制，默认拒绝。
 *
 * 语义：
 * - 仅对策略表中登记的路径放行到对应权限校验；
 * - 任何未登记的 /api 路径一律以 INSUFFICIENT_PERMISSION 拒绝（默认拒绝，不静默放行）；
 * - 未认证/已过期/已撤销 -> 401，权限不足 -> 403，原因码写入响应体，可区分。
 */
@Component
public class SecurityInterceptor implements HandlerInterceptor {

    /** 认证上下文在请求属性中的键，供 Controller 取当前用户。 */
    public static final String AUTH_CONTEXT_ATTR = SecurityInterceptor.class.getName() + ".AUTH_CONTEXT";

    /** 路径 -> 所需权限。未登记的受保护路径默认拒绝。 */
    private static final Map<String, String> POLICY = new LinkedHashMap<>();

    static {
        // 登出是自助操作：仅需任一已认证用户都具备的基础权限；
        // 撤销他人会话的提权判定在 AuthController 内单独要求 admin:write。
        POLICY.put("/api/auth/logout", "profile:read");
        POLICY.put("/api/demo/profile", "profile:read");
        POLICY.put("/api/demo/admin", "admin:read");
        POLICY.put("/api/demo/audits", "admin:read");
    }

    /** 默认拒绝使用的权限名，表示该路径根本未被声明允许。 */
    private static final String UNDECLARED_PERMISSION = "<undeclared-resource>";

    private final AccessGuard accessGuard;
    private final ObjectMapper objectMapper;

    public SecurityInterceptor(AccessGuard accessGuard, ObjectMapper objectMapper) {
        this.accessGuard = accessGuard;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        // 放行 CORS 预检
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String path = request.getRequestURI();
        String requiredPermission = POLICY.get(path);
        if (requiredPermission == null) {
            // 默认拒绝：未声明允许的 /api 访问
            writeDeny(request, response,
                    AccessDecision.deny(DecisionReason.INSUFFICIENT_PERMISSION,
                            "access to undeclared resource is denied by default", UNDECLARED_PERMISSION));
            return false;
        }

        AccessDecision decision = accessGuard.decide(request.getHeader("Authorization"), requiredPermission);
        if (!decision.allowed()) {
            writeDeny(request, response, decision);
            return false;
        }

        AuthContext context = decision.context();
        request.setAttribute(AUTH_CONTEXT_ATTR, context);
        return true;
    }

    private void writeDeny(HttpServletRequest request, HttpServletResponse response,
                           AccessDecision decision) throws Exception {
        DecisionReason reason = decision.reason();
        HttpStatus status = (reason == DecisionReason.INSUFFICIENT_PERMISSION)
                ? HttpStatus.FORBIDDEN
                : HttpStatus.UNAUTHORIZED;

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        ErrorResponse body = new ErrorResponse(
                Instant.now(),
                status.value(),
                status.getReasonPhrase(),
                reason,
                decision.message(),
                request.getRequestURI());
        objectMapper.writeValue(response.getWriter(), body);
    }
}
