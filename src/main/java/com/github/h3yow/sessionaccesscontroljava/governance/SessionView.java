package com.github.h3yow.sessionaccesscontroljava.governance;

import java.time.Instant;

/**
 * 会话列表条目（对外视图）。
 * 刻意不包含任何访问/刷新凭证内容，只保留可识别信息。
 */
public record SessionView(
        String sessionId,
        Instant createdAt,
        Instant lastActivityAt,
        Instant refreshExpiresAt,
        boolean current
) {
}
