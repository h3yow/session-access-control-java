package com.github.h3yow.sessionaccesscontroljava.access;

/** 访问被拒绝的可区分原因。 */
public enum AccessDeniedReason {
    MISSING_CREDENTIAL,
    UNKNOWN_TOKEN,
    TOKEN_EXPIRED,
    TOKEN_REVOKED,
    SESSION_REVOKED,
    /** 会话因闲置超时自动失效（区别于凭证自身的绝对过期）。 */
    SESSION_IDLE_TIMEOUT,
    /** 会话因超出单用户活跃会话容量上限被淘汰。 */
    SESSION_EVICTED,
    /** 会话的刷新凭证已到达绝对过期时间（区别于闲置失效）。 */
    SESSION_EXPIRED,
    INSUFFICIENT_PERMISSION
}
