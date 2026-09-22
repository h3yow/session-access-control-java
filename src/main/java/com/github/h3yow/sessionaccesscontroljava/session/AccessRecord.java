package com.github.h3yow.sessionaccesscontroljava.session;

import java.time.Instant;

/** 已签发的访问凭证记录（支持即时撤销校验与过期判定）。 */
public class AccessRecord {

    private final String accessToken;
    private final String sessionId;
    private final String username;
    private final Instant expiresAt;
    private volatile boolean revoked;

    public AccessRecord(String accessToken, String sessionId, String username,
                        Instant expiresAt, boolean revoked) {
        this.accessToken = accessToken;
        this.sessionId = sessionId;
        this.username = username;
        this.expiresAt = expiresAt;
        this.revoked = revoked;
    }

    public String getAccessToken() { return accessToken; }
    public String getSessionId() { return sessionId; }
    public String getUsername() { return username; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
}
