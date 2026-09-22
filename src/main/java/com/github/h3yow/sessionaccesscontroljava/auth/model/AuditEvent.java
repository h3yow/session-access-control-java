package com.github.h3yow.sessionaccesscontroljava.auth.model;

import java.time.Instant;

/**
 * 可追溯的审计记录。
 */
public record AuditEvent(
        Instant timestamp,
        String action,
        String username,
        String sessionId,
        String outcome,
        DecisionReason reason,
        String detail
) {
}
