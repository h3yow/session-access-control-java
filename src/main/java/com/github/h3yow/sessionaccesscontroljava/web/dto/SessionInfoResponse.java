package com.github.h3yow.sessionaccesscontroljava.web.dto;

import java.time.Instant;

/** 列表中单条会话的对外表示：不含任何凭证内容。 */
public record SessionInfoResponse(
        String sessionId,
        Instant createdAt,
        Instant lastActivityAt,
        boolean current
) {
}
