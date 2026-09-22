package com.github.h3yow.sessionaccesscontroljava.auth.model;

import java.time.Instant;

/**
 * 刷新凭证索引条目。即使凭证被轮换（REPLACED）或随链撤销（REVOKED）也保留索引：
 * 这样旧凭证被重复使用时可以识别为“重放”，从而使会话链整体失效，
 * 而不是被当作未知凭证（两者返回可区分原因）。
 *
 * 并发语义：状态变更必须在 {@code RefreshTokenStore.withTokenLock} 保护下进行。
 */
public class RefreshTokenEntry {

    public enum Status { ACTIVE, REPLACED, REVOKED }

    private final String tokenHash;
    private final String sessionId;
    private final Instant issuedAt;
    private final Instant expiresAt;

    private volatile Status status;
    private volatile Instant replacedAt;
    private volatile String replacedByHash;

    public RefreshTokenEntry(String tokenHash, String sessionId, Instant issuedAt, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.sessionId = sessionId;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.status = Status.ACTIVE;
    }

    public String getTokenHash() { return tokenHash; }
    public String getSessionId() { return sessionId; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Status getStatus() { return status; }
    public Instant getReplacedAt() { return replacedAt; }
    public String getReplacedByHash() { return replacedByHash; }

    /** 是否过期。 */
    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }

    /**
     * 标记为已被新凭证轮换。仅 ACTIVE 可转换，幂等安全。
     */
    public void markReplaced(String newTokenHash, Instant now) {
        if (status != Status.ACTIVE) {
            return;
        }
        this.status = Status.REPLACED;
        this.replacedByHash = newTokenHash;
        this.replacedAt = now;
    }

    /**
     * 标记为已撤销（随会话链主动撤销或重放失效）。REPLACED 也可以转为 REVOKED，
     * 但 ACTIVE 转为 REVOKED 用于主动撤销。
     */
    public void markRevoked() {
        this.status = Status.REVOKED;
    }
}
