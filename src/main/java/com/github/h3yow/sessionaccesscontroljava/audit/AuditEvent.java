package com.github.h3yow.sessionaccesscontroljava.audit;

import java.time.Instant;

/** 审计事件。 */
public record AuditEvent(
        Instant timestamp,
        String action,
        String subject,
        String result,
        String detail
) {
}
