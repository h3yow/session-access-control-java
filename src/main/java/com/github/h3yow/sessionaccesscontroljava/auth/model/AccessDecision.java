package com.github.h3yow.sessionaccesscontroljava.auth.model;

/**
 * 授权判定结果。allowed=false 时 reason 必须给出可区分原因。
 */
public record AccessDecision(
        boolean allowed,
        DecisionReason reason,
        String message,
        AuthContext context,
        String requiredPermission
) {

    public static AccessDecision allow(AuthContext context, String requiredPermission) {
        return new AccessDecision(true, DecisionReason.ALLOWED, "allowed", context, requiredPermission);
    }

    public static AccessDecision deny(DecisionReason reason, String message, String requiredPermission) {
        return new AccessDecision(false, reason, message, null, requiredPermission);
    }
}
