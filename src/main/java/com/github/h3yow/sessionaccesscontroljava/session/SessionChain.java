package com.github.h3yow.sessionaccesscontroljava.session;

import java.time.Instant;

/**
 * 一条会话链：登录产生，每次刷新轮换 refresh 凭证。
 * 检测到已轮换旧凭证被重复使用时整条链失效（复用检测 / 重放攻击）。
 *
 * 治理字段：
 * - createdAt       登录时间（链创建时间，不可变）
 * - lastActivityAt  最近一次活动时间（访问放行或刷新成功时推进；会话列表"当前在用"判断与
 *                   闲置/淘汰判定都基于它）
 *
 * 终态语义：REVOKED / IDLE_TIMEOUT / EVICTED / EXPIRED 均为终态，不可重新激活。
 */
public class SessionChain {

    private final String sessionId;
    private final String username;
    private volatile String currentRefreshToken;
    private final Instant refreshTokenExpiresAt;
    private final Instant createdAt;
    private volatile Instant lastActivityAt;
    private volatile SessionState state;

    public SessionChain(String sessionId, String username, String currentRefreshToken,
                        Instant refreshTokenExpiresAt, SessionState state,
                        Instant createdAt, Instant lastActivityAt) {
        this.sessionId = sessionId;
        this.username = username;
        this.currentRefreshToken = currentRefreshToken;
        this.refreshTokenExpiresAt = refreshTokenExpiresAt;
        this.state = state;
        this.createdAt = createdAt;
        this.lastActivityAt = lastActivityAt;
    }

    /** 兼容旧调用：以链创建时间同时作为最近活动时间。 */
    public SessionChain(String sessionId, String username, String currentRefreshToken,
                        Instant refreshTokenExpiresAt, SessionState state) {
        this(sessionId, username, currentRefreshToken, refreshTokenExpiresAt, state,
                Instant.EPOCH, Instant.EPOCH);
    }

    public String getSessionId() { return sessionId; }
    public String getUsername() { return username; }
    public String getCurrentRefreshToken() { return currentRefreshToken; }
    public void setCurrentRefreshToken(String token) { this.currentRefreshToken = token; }
    public Instant getRefreshTokenExpiresAt() { return refreshTokenExpiresAt; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastActivityAt() { return lastActivityAt; }
    public void setLastActivityAt(Instant at) { this.lastActivityAt = at; }
    public SessionState getState() { return state; }
    public void setState(SessionState state) { this.state = state; }
}
