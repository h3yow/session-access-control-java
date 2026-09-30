package com.github.h3yow.sessionaccesscontroljava.auth;

/**
 * 认证类操作结果原因（可区分、可解释）。
 *
 * 时间类失效刻意分为两个原因：
 * - REFRESH_TOKEN_EXPIRED：凭证到达绝对过期时间；
 * - SESSION_IDLE：凭证本身可能还没到绝对过期，但会话闲置超过治理窗口。
 */
public enum AuthOutcome {
    LOGIN_SUCCESS,
    INVALID_CREDENTIALS,
    ACCOUNT_LOCKED,
    REFRESH_SUCCESS,
    REFRESH_TOKEN_UNKNOWN,
    REFRESH_TOKEN_EXPIRED,
    SESSION_REVOKED,
    REFRESH_TOKEN_REUSED,
    /** 会话因闲置超时自动失效（与凭证绝对过期可区分）。 */
    SESSION_IDLE,
    /** 会话因用户活跃会话数超上限被淘汰。 */
    SESSION_EVICTED,
    REVOKE_SUCCESS,
    REVOKE_NOT_FOUND
}
