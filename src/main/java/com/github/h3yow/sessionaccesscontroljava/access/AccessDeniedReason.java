package com.github.h3yow.sessionaccesscontroljava.access;

/** 访问被拒绝的可区分原因。 */
public enum AccessDeniedReason {
    MISSING_CREDENTIAL,
    UNKNOWN_TOKEN,
    TOKEN_EXPIRED,
    TOKEN_REVOKED,
    SESSION_REVOKED,
    INSUFFICIENT_PERMISSION
}
