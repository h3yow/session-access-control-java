package com.github.h3yow.sessionaccesscontroljava.session;

import java.time.Instant;

/**
 * 已签发的访问凭证记录（支持即时撤销校验与过期判定）。
 *
 * 撤销带原因：主动撤销 / 闲置超时 / 容量淘汰分别标记，使访问拒绝原因可区分。
 */
public class AccessRecord {

    private final String accessToken;
    private final String sessionId;
    private final String username;
    private final Instant expiresAt;
    private volatile AccessRevokeReason revokeReason;

    public AccessRecord(String accessToken, String sessionId, String username,
                        Instant expiresAt, AccessRevokeReason revokeReason) {
        this.accessToken = accessToken;
        this.sessionId = sessionId;
        this.username = username;
        this.expiresAt = expiresAt;
        this.revokeReason = revokeReason;
    }

    /** 兼容旧调用：以布尔撤销标记构造。 */
    public AccessRecord(String accessToken, String sessionId, String username,
                        Instant expiresAt, boolean revoked) {
        this(accessToken, sessionId, username, expiresAt,
                revoked ? AccessRevokeReason.SESSION_REVOKED : null);
    }

    public String getAccessToken() { return accessToken; }
    public String getSessionId() { return sessionId; }
    public String getUsername() { return username; }
    public Instant getExpiresAt() { return expiresAt; }

    public AccessRevokeReason getRevokeReason() { return revokeReason; }
    public void setRevokeReason(AccessRevokeReason reason) { this.revokeReason = reason; }

    public boolean isRevoked() { return revokeReason != null; }
    public void setRevoked(boolean revoked) {
        this.revokeReason = revoked ? AccessRevokeReason.SESSION_REVOKED : null;
    }
}
