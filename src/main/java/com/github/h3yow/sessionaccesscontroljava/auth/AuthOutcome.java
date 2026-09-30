package com.github.h3yow.sessionaccesscontroljava.auth;

/** 认证类操作结果原因（可区分、可解释）。 */
public enum AuthOutcome {
    LOGIN_SUCCESS,
    INVALID_CREDENTIALS,
    ACCOUNT_LOCKED,
    REFRESH_SUCCESS,
    REFRESH_TOKEN_UNKNOWN,
    REFRESH_TOKEN_EXPIRED,
    SESSION_REVOKED,
    REFRESH_TOKEN_REUSED,
    REVOKE_SUCCESS,
    REVOKE_NOT_FOUND,
    /** 刷新时会话已因闲置超时自动失效（区别于 REFRESH_TOKEN_EXPIRED 绝对过期）。 */
    SESSION_IDLE_TIMEOUT,
    /** 刷新时会话已因超出容量上限被淘汰。 */
    SESSION_EVICTED
}
