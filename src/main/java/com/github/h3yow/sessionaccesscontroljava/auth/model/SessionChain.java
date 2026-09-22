package com.github.h3yow.sessionaccesscontroljava.auth.model;

import java.time.Instant;
import java.util.Set;

/**
 * 会话链：一个登录会话对应一条链。
 * 每次刷新轮换链上当前的访问/刷新凭证；链被撤销时，链上所有凭证同时失效。
 *
 * 并发语义：链上所有状态变更（轮换、撤销）必须在 {@code TokenService} 持有的
 * “刷新凭证锁 + 链锁”保护下进行，字段使用 volatile 保证撤销等状态对并发读可见。
 */
public class SessionChain {

    private final String sessionId;
    private final String username;
    private final Set<Role> roles;
    private final Instant createdAt;

    private volatile String currentAccessTokenHash;
    private volatile Instant accessTokenExpiresAt;
    private volatile String currentRefreshTokenHash;
    private volatile Instant refreshTokenExpiresAt;
    private volatile long rotationVersion;
    private volatile boolean revoked;
    private volatile DecisionReason revokeReason;
    private volatile Instant revokedAt;

    public SessionChain(String sessionId, String username, Set<Role> roles, Instant createdAt) {
        this.sessionId = sessionId;
        this.username = username;
        this.roles = Set.copyOf(roles);
        this.createdAt = createdAt;
        this.rotationVersion = 0;
    }

    public String getSessionId() { return sessionId; }
    public String getUsername() { return username; }
    public Set<Role> getRoles() { return roles; }
    public Instant getCreatedAt() { return createdAt; }

    public String getCurrentAccessTokenHash() { return currentAccessTokenHash; }
    public Instant getAccessTokenExpiresAt() { return accessTokenExpiresAt; }
    public String getCurrentRefreshTokenHash() { return currentRefreshTokenHash; }
    public Instant getRefreshTokenExpiresAt() { return refreshTokenExpiresAt; }
    public long getRotationVersion() { return rotationVersion; }
    public boolean isRevoked() { return revoked; }
    public DecisionReason getRevokeReason() { return revokeReason; }
    public Instant getRevokedAt() { return revokedAt; }

    /**
     * 写入首组凭证（登录时）。
     */
    public void initTokens(String accessTokenHash, Instant accessExpiresAt,
                           String refreshTokenHash, Instant refreshExpiresAt) {
        this.currentAccessTokenHash = accessTokenHash;
        this.accessTokenExpiresAt = accessExpiresAt;
        this.currentRefreshTokenHash = refreshTokenHash;
        this.refreshTokenExpiresAt = refreshExpiresAt;
        this.rotationVersion = 1;
    }

    /**
     * 轮换到新一组凭证（刷新时），仅当链未撤销时允许。
     *
     * @return true 表示轮换成功；false 表示链已被撤销
     */
    public boolean rotate(String newAccessTokenHash, Instant newAccessExpiresAt,
                          String newRefreshTokenHash, Instant newRefreshExpiresAt) {
        if (revoked) {
            return false;
        }
        this.currentAccessTokenHash = newAccessTokenHash;
        this.accessTokenExpiresAt = newAccessExpiresAt;
        this.currentRefreshTokenHash = newRefreshTokenHash;
        this.refreshTokenExpiresAt = newRefreshExpiresAt;
        this.rotationVersion++;
        return true;
    }

    /**
     * 撤销整条会话链。撤销是终态且幂等：重复撤销不覆盖首次撤销原因。
     */
    public void revoke(DecisionReason reason, Instant now) {
        if (this.revoked) {
            return;
        }
        this.revoked = true;
        this.revokeReason = reason;
        this.revokedAt = now;
    }
}
