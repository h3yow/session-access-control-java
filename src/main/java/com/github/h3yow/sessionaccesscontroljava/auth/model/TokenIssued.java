package com.github.h3yow.sessionaccesscontroljava.auth.model;

import java.time.Instant;

/**
 * 登录 / 刷新后的凭证签发结果。success=false 时 reason 给出可区分原因。
 */
public record TokenIssued(
        boolean success,
        DecisionReason reason,
        String message,
        String sessionId,
        String accessToken,
        String refreshToken,
        Instant accessTokenExpiresAt,
        Instant refreshTokenExpiresAt
) {

    public static TokenIssued fail(DecisionReason reason, String message) {
        return new TokenIssued(false, reason, message, null, null, null, null, null);
    }
}
