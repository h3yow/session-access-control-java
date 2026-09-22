package com.github.h3yow.sessionaccesscontroljava.auth.security;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.auth.model.AuthContext;
import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;
import com.github.h3yow.sessionaccesscontroljava.auth.model.Role;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 访问控制守卫：
 * 1) 认证：校验短期访问凭证，区分未认证 / 已过期 / 已撤销；
 * 2) 授权：聚合角色权限做精确匹配，默认拒绝——未声明允许的访问一律拒绝，
 *    权限不足返回可区分原因 INSUFFICIENT_PERMISSION。
 *
 * 每一条判定（允许或拒绝）都写审计；审计失败不影响判定结果。
 */
@Service
public class AccessGuard {

    private static final String BEARER_PREFIX = "Bearer ";

    private final TokenService tokenService;
    private final AuditService auditService;

    public AccessGuard(TokenService tokenService, AuditService auditService) {
        this.tokenService = tokenService;
        this.auditService = auditService;
    }

    public AccessDecision decide(String authorizationHeader, String requiredPermission) {
        String token = extractBearer(authorizationHeader);
        AtomicReference<DecisionReason> reasonOut = new AtomicReference<>();
        AuthContext context = tokenService.authenticateAccessToken(token, reasonOut);

        if (context == null) {
            DecisionReason reason = reasonOut.get();
            String message = switch (reason) {
                case EXPIRED -> "access token expired";
                case REVOKED -> "session or token revoked";
                default -> "missing or unrecognized access token";
            };
            AccessDecision denied = AccessDecision.deny(reason, message, requiredPermission);
            auditService.record("ACCESS", null, null, "DENIED", reason,
                    "authz required=" + requiredPermission + " basis=" + message);
            return denied;
        }

        Set<String> permissions = aggregatePermissions(context.roles());
        if (requiredPermission == null || !permissions.contains(requiredPermission)) {
            AccessDecision denied = AccessDecision.deny(DecisionReason.INSUFFICIENT_PERMISSION,
                    "permission '" + requiredPermission + "' not granted", requiredPermission);
            auditService.record("ACCESS", context.username(), context.sessionId(), "DENIED",
                    DecisionReason.INSUFFICIENT_PERMISSION,
                    "authz required=" + requiredPermission + " granted=" + permissions);
            return denied;
        }

        AccessDecision allowed = AccessDecision.allow(context, requiredPermission);
        auditService.record("ACCESS", context.username(), context.sessionId(), "SUCCESS",
                DecisionReason.ALLOWED,
                "authz required=" + requiredPermission + " granted roles=" + context.roles());
        return allowed;
    }

    private String extractBearer(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        String trimmed = header.trim();
        if (trimmed.length() <= BEARER_PREFIX.length()) {
            return null;
        }
        String prefix = trimmed.substring(0, BEARER_PREFIX.length());
        if (!prefix.equalsIgnoreCase(BEARER_PREFIX)) {
            return null;
        }
        return trimmed.substring(BEARER_PREFIX.length()).trim();
    }

    /** 聚合用户所有角色的权限集合。 */
    static Set<String> aggregatePermissions(Set<Role> roles) {
        Set<String> all = new HashSet<>();
        for (Role role : roles) {
            all.addAll(role.permissions());
        }
        return Set.copyOf(all);
    }
}
