package com.github.h3yow.sessionaccesscontroljava.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.sessionaccesscontroljava.access.AccessControlService;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDeniedReason;
import com.github.h3yow.sessionaccesscontroljava.access.RequirePermission;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Map;

/**
 * 对受保护路径执行统一认证与授权拦截。
 * 处理器（或其所属类）必须显式标注 {@link RequirePermission}，否则按默认拒绝处理。
 */
@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationInterceptor.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final AccessControlService accessControlService;

    public AuthorizationInterceptor(AccessControlService accessControlService) {
        this.accessControlService = accessControlService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            return true;
        }

        String requiredPermission = null;
        if (handler instanceof HandlerMethod handlerMethod) {
            RequirePermission annotation = handlerMethod.getMethodAnnotation(RequirePermission.class);
            if (annotation == null) {
                annotation = handlerMethod.getBeanType().getAnnotation(RequirePermission.class);
            }
            requiredPermission = annotation == null ? null : annotation.value();
        }

        String token = extractBearerToken(request.getHeader("Authorization"));
        AccessDecision decision = accessControlService.decide(token, requiredPermission);

        if (!decision.allowed()) {
            writeDeny(response, decision, request.getRequestURI());
            return false;
        }
        request.setAttribute("username", decision.username());
        request.setAttribute("sessionId", decision.sessionId());
        return true;
    }

    private String extractBearerToken(String header) {
        if (header == null || !header.startsWith(BEARER_PREFIX)) {
            return null;
        }
        String token = header.substring(BEARER_PREFIX.length()).trim();
        return token.isEmpty() ? null : token;
    }

    private void writeDeny(HttpServletResponse response, AccessDecision decision, String path) throws Exception {
        HttpStatus status = mapStatus(decision.deniedReason());
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        Map<String, Object> body = Map.of(
                "success", false,
                "reason", decision.deniedReason().name(),
                "message", decision.message(),
                "path", path);
        log.info("http-deny-response path={} status={} reason={}", path, status.value(), decision.deniedReason());
        response.getWriter().write(MAPPER.writeValueAsString(body));
    }

    private HttpStatus mapStatus(AccessDeniedReason reason) {
        return switch (reason) {
            case MISSING_CREDENTIAL, UNKNOWN_TOKEN -> HttpStatus.UNAUTHORIZED;
            case TOKEN_EXPIRED, TOKEN_REVOKED, SESSION_REVOKED,
                    SESSION_IDLE_TIMEOUT, SESSION_EVICTED, SESSION_EXPIRED -> HttpStatus.UNAUTHORIZED;
            case INSUFFICIENT_PERMISSION -> HttpStatus.FORBIDDEN;
        };
    }
}
