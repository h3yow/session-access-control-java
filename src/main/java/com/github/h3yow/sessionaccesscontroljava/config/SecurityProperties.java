package com.github.h3yow.sessionaccesscontroljava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 安全策略配置（可通过 application.properties 覆盖）。
 */
@Component
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    /** 访问凭证有效期（秒），短期。 */
    private long accessTokenTtlSeconds = 900;

    /** 刷新凭证有效期（秒），长期。 */
    private long refreshTokenTtlSeconds = 1800;

    /** 连续登录失败多少次后锁定账户。 */
    private int maxLoginFailures = 5;

    /** 锁定时长（秒）。 */
    private long lockDurationSeconds = 300;

    /** 凭证随机字节数。 */
    private int tokenBytes = 32;

    public long getAccessTokenTtlSeconds() { return accessTokenTtlSeconds; }
    public void setAccessTokenTtlSeconds(long v) { this.accessTokenTtlSeconds = v; }

    public long getRefreshTokenTtlSeconds() { return refreshTokenTtlSeconds; }
    public void setRefreshTokenTtlSeconds(long v) { this.refreshTokenTtlSeconds = v; }

    public int getMaxLoginFailures() { return maxLoginFailures; }
    public void setMaxLoginFailures(int v) { this.maxLoginFailures = v; }

    public long getLockDurationSeconds() { return lockDurationSeconds; }
    public void setLockDurationSeconds(long v) { this.lockDurationSeconds = v; }

    public int getTokenBytes() { return tokenBytes; }
    public void setTokenBytes(int v) { this.tokenBytes = v; }
}
