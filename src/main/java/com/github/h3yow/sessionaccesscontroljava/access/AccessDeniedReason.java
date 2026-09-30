package com.github.h3yow.sessionaccesscontroljava.access;

/** 访问被拒绝的可区分原因。 */
public enum AccessDeniedReason {
    MISSING_CREDENTIAL,
    UNKNOWN_TOKEN,
    TOKEN_EXPIRED,
    TOKEN_REVOKED,
    SESSION_REVOKED,
    /** 所属会话因闲置超时失效。 */
    SESSION_IDLE,
    /** 所属会话因容量超限被淘汰。 */
    SESSION_EVICTED,
    /** 所属会话已达绝对过期时间。 */
    SESSION_EXPIRED,
    INSUFFICIENT_PERMISSION
}
