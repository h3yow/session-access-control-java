package com.github.h3yow.sessionaccesscontroljava.access;

/** 访问判定结果。 */
public record AccessDecision(
        boolean allowed,
        AccessDeniedReason deniedReason,
        String username,
        String sessionId,
        String message
) {
    public static AccessDecision deny(AccessDeniedReason reason, String message) {
        return new AccessDecision(false, reason, null, null, message);
    }

    public static AccessDecision allow(String username, String sessionId) {
        return new AccessDecision(true, null, username, sessionId, "access granted");
    }
}
