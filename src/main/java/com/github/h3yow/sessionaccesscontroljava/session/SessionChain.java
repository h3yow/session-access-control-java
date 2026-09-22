package com.github.h3yow.sessionaccesscontroljava.session;

import java.time.Instant;

/**
 * 一条会话链：登录产生，每次刷新轮换 refresh 凭证。
 * 检测到已轮换旧凭证被重复使用时整条链失效（复用检测 / 重放攻击）。
 */
public class SessionChain {

    private final String sessionId;
    private final String username;
    private volatile String currentRefreshToken;
    private final Instant refreshTokenExpiresAt;
    private volatile SessionState state;

    public SessionChain(String sessionId, String username, String currentRefreshToken,
                        Instant refreshTokenExpiresAt, SessionState state) {
        this.sessionId = sessionId;
        this.username = username;
        this.currentRefreshToken = currentRefreshToken;
        this.refreshTokenExpiresAt = refreshTokenExpiresAt;
        this.state = state;
    }

    public String getSessionId() { return sessionId; }
    public String getUsername() { return username; }
    public String getCurrentRefreshToken() { return currentRefreshToken; }
    public void setCurrentRefreshToken(String token) { this.currentRefreshToken = token; }
    public Instant getRefreshTokenExpiresAt() { return refreshTokenExpiresAt; }
    public SessionState getState() { return state; }
    public void setState(SessionState state) { this.state = state; }
}
