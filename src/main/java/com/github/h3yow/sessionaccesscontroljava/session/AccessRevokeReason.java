package com.github.h3yow.sessionaccesscontroljava.session;

/**
 * 访问凭证被撤销的原因（空表示未撤销）。
 * 用于让访问拒绝原因区分"会话主动撤销 / 闲置 / 淘汰"，而不是一律 TOKEN_REVOKED。
 */
public enum AccessRevokeReason {
    SESSION_REVOKED,
    IDLE_TIMEOUT,
    EVICTED
}
