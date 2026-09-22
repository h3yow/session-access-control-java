package com.github.h3yow.sessionaccesscontroljava.auth.web;

import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;

import java.time.Instant;

/**
 * 统一错误响应体，reason 为机器可区分的原因码。
 */
public record ErrorResponse(
        Instant timestamp,
        int status,
        String error,
        DecisionReason reason,
        String message,
        String path
) {
}
