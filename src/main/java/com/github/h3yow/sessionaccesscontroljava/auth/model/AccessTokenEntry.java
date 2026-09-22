package com.github.h3yow.sessionaccesscontroljava.auth.model;

import java.time.Instant;

/**
 * 短期访问凭证索引条目。
 * 即使凭证被轮换（REPLACED）或随链撤销（REVOKED）也保留索引，
 * 使“已撤销”与“未认证（查无此凭证）”、“已过期”可区分判定。
 */
public class AccessTokenEntry {

    public enum Status { ACTIVE, REPLACED, REVOKED }

    private final String tokenHash;
    private final String sessionId;
    private final Instant expiresAt;
    private volatile Status status;

    public AccessTokenEntry(String tokenHash, String sessionId, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.sessionId = sessionId;
        this.expiresAt = expiresAt;
        this.status = Status.ACTIVE;
    }

    public String getTokenHash() { return tokenHash; }
    public String getSessionId() { return sessionId; }
    public Instant getExpiresAt() { return expiresAt; }
    public Status getStatus() { return status; }

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    public void markReplaced() {
        if (status == Status.ACTIVE) {
            this.status = Status.REPLACED;
        }
    }

    public void markRevoked() {
        this.status = Status.REVOKED;
    }
}
