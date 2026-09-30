package com.github.h3yow.sessionaccesscontroljava.auth;

import com.github.h3yow.sessionaccesscontroljava.audit.AuditService;
import com.github.h3yow.sessionaccesscontroljava.clock.TickClock;
import com.github.h3yow.sessionaccesscontroljava.session.AccessRecord;
import com.github.h3yow.sessionaccesscontroljava.session.SessionChain;
import com.github.h3yow.sessionaccesscontroljava.session.SessionRepository;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import com.github.h3yow.sessionaccesscontroljava.token.TokenIssuer;
import com.github.h3yow.sessionaccesscontroljava.token.TokenPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * 认证服务：登录签发凭证、刷新轮换（含复用检测）、主动撤销。
 *
 * 刷新并发与复用语义：
 * - 轮换在会话监视器内 CAS 完成，同一 refresh 凭证并发刷新只有一次成功。
 * - 旧凭证轮换后保留可解析索引，但不再是链上当前凭证；旧凭证再次出现即判定 REUSED，
 *   整条会话链（含所有访问凭证）立即失效。
 */
@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final SessionRepository sessionRepository;
    private final UserDirectory userDirectory;
    private final PasswordHasher passwordHasher;
    private final LoginFailureTracker failureTracker;
    private final TokenIssuer tokenIssuer;
    private final TickClock clock;
    private final AuditService auditService;

    private final Duration accessTtl;
    private final Duration refreshTtl;
    private final Duration idleTimeout;
    private final int maxSessionsPerUser;

    public AuthService(SessionRepository sessionRepository,
                       UserDirectory userDirectory,
                       PasswordHasher passwordHasher,
                       LoginFailureTracker failureTracker,
                       TokenIssuer tokenIssuer,
                       TickClock clock,
                       AuditService auditService,
                       @Value("${auth.token.access-ttl:PT15M}") Duration accessTtl,
                       @Value("${auth.token.refresh-ttl:PT12H}") Duration refreshTtl,
                       @Value("${auth.session.idle-timeout:PT30M}") Duration idleTimeout,
                       @Value("${auth.session.max-per-user:5}") int maxSessionsPerUser) {
        this.sessionRepository = sessionRepository;
        this.userDirectory = userDirectory;
        this.passwordHasher = passwordHasher;
        this.failureTracker = failureTracker;
        this.tokenIssuer = tokenIssuer;
        this.clock = clock;
        this.auditService = auditService;
        this.accessTtl = accessTtl;
        this.refreshTtl = refreshTtl;
        this.idleTimeout = idleTimeout;
        this.maxSessionsPerUser = maxSessionsPerUser;
    }

    /** 登录：校验锁定状态与口令，成功则签发一条新会话链与凭证对。 */
    public AuthResult login(String username, String rawPassword) {
        log.info("login-attempt username={}", username);
        if (username == null || rawPassword == null) {
            auditService.record("LOGIN", String.valueOf(username), "INVALID_CREDENTIALS", "missing username or password");
            return AuthResult.failure(AuthOutcome.INVALID_CREDENTIALS, "username and password are required");
        }

        if (failureTracker.isLocked(username)) {
            log.warn("login-denied username={} reason=ACCOUNT_LOCKED", username);
            auditService.record("LOGIN", username, "ACCOUNT_LOCKED", "too many consecutive failures");
            return AuthResult.failure(AuthOutcome.ACCOUNT_LOCKED, "account temporarily locked due to consecutive failed logins");
        }

        Optional<AppUser> userOpt = userDirectory.findByUsername(username);
        if (userOpt.isEmpty() || !passwordHasher.matches(rawPassword, userOpt.get().passwordHash())) {
            boolean nowLocked = failureTracker.recordFailure(username);
            if (nowLocked) {
                log.warn("login-denied username={} reason=ACCOUNT_LOCKED (threshold reached on this attempt)", username);
                auditService.record("LOGIN", username, "ACCOUNT_LOCKED",
                        "failure threshold reached on this attempt");
                return AuthResult.failure(AuthOutcome.ACCOUNT_LOCKED,
                        "account locked: consecutive failure threshold reached");
            }
            log.warn("login-denied username={} reason=INVALID_CREDENTIALS", username);
            auditService.record("LOGIN", username, "INVALID_CREDENTIALS", "bad username or password");
            return AuthResult.failure(AuthOutcome.INVALID_CREDENTIALS, "invalid username or password");
        }

        failureTracker.reset(username);
        TokenPair tokens = issueNewSession(username);
        log.info("login-success username={} accessExpiresAt={} refreshExpiresAt={}",
                username, tokens.accessTokenExpiresAt(), tokens.refreshTokenExpiresAt());
        auditService.record("LOGIN", username, "LOGIN_SUCCESS", "tokens issued");
        return AuthResult.success(AuthOutcome.LOGIN_SUCCESS, tokens, "login successful");
    }

    /** 刷新：校验存在性/状态/过期，原子轮换；检测到旧凭证复用则整条链失效。 */
    public AuthResult refresh(String refreshToken) {
        log.info("refresh-attempt refreshTokenPrefix={}", prefix(refreshToken));
        if (refreshToken == null || refreshToken.isBlank()) {
            auditService.record("REFRESH", "anonymous", "REFRESH_TOKEN_UNKNOWN", "missing refresh token");
            return AuthResult.failure(AuthOutcome.REFRESH_TOKEN_UNKNOWN, "refresh token is required");
        }

        Optional<SessionChain> chainOpt = sessionRepository.findByRefreshToken(refreshToken);
        if (chainOpt.isEmpty()) {
            log.warn("refresh-denied reason=REFRESH_TOKEN_UNKNOWN prefix={}", prefix(refreshToken));
            auditService.record("REFRESH", "anonymous", "REFRESH_TOKEN_UNKNOWN", "token not found prefix=" + prefix(refreshToken));
            return AuthResult.failure(AuthOutcome.REFRESH_TOKEN_UNKNOWN, "unknown refresh token");
        }

        SessionChain chain = chainOpt.get();
        // 固定加锁顺序：先用户锁后会话锁（与登录建档/淘汰一致），杜绝死锁与容量竞争误算
        synchronized (sessionRepository.userLock(chain.getUsername())) {
            synchronized (chain) {
                SessionState state = chain.getState();
                if (state == SessionState.REVOKED) {
                    log.warn("refresh-denied sessionId={} username={} reason=SESSION_REVOKED",
                            chain.getSessionId(), chain.getUsername());
                    auditService.record("REFRESH", chain.getUsername(), "SESSION_REVOKED",
                            "sessionId=" + chain.getSessionId());
                    return AuthResult.failure(AuthOutcome.SESSION_REVOKED, "session has been revoked");
                }
                if (state == SessionState.IDLE_TIMEOUT) {
                    log.warn("refresh-denied sessionId={} username={} reason=SESSION_IDLE_TIMEOUT lastActivityAt={}",
                            chain.getSessionId(), chain.getUsername(), chain.getLastActivityAt());
                    auditService.record("REFRESH", chain.getUsername(), "SESSION_IDLE_TIMEOUT",
                            "idle timeout sessionId=" + chain.getSessionId());
                    return AuthResult.failure(AuthOutcome.SESSION_IDLE_TIMEOUT,
                            "session has timed out due to inactivity");
                }
                if (state == SessionState.EVICTED) {
                    log.warn("refresh-denied sessionId={} username={} reason=SESSION_EVICTED",
                            chain.getSessionId(), chain.getUsername());
                    auditService.record("REFRESH", chain.getUsername(), "SESSION_EVICTED",
                            "evicted by capacity limit sessionId=" + chain.getSessionId());
                    return AuthResult.failure(AuthOutcome.SESSION_EVICTED,
                            "session was evicted due to the active session capacity limit");
                }

                Instant now = clock.now();
                // 绝对过期优先：刷新凭证的绝对到期与闲置失效必须可区分
                if (!now.isBefore(chain.getRefreshTokenExpiresAt())) {
                    chain.setState(SessionState.EXPIRED);
                    log.warn("refresh-denied sessionId={} username={} reason=REFRESH_TOKEN_EXPIRED expiredAt={}",
                            chain.getSessionId(), chain.getUsername(), chain.getRefreshTokenExpiresAt());
                    auditService.record("REFRESH", chain.getUsername(), "REFRESH_TOKEN_EXPIRED",
                            "absolute expiry sessionId=" + chain.getSessionId());
                    return AuthResult.failure(AuthOutcome.REFRESH_TOKEN_EXPIRED, "refresh token has expired");
                }
                // 闲置治理：一段时间无访问也无刷新 -> 自动失效（区别于绝对过期）
                if (sessionRepository.evaluateIdle(chain, now, idleTimeout) == SessionState.IDLE_TIMEOUT) {
                    log.warn("refresh-denied sessionId={} username={} reason=SESSION_IDLE_TIMEOUT lastActivityAt={} idleTimeout={}",
                            chain.getSessionId(), chain.getUsername(), chain.getLastActivityAt(), idleTimeout);
                    auditService.record("REFRESH", chain.getUsername(), "SESSION_IDLE_TIMEOUT",
                            "idle timeout on refresh sessionId=" + chain.getSessionId()
                                    + " lastActivityAt=" + chain.getLastActivityAt());
                    return AuthResult.failure(AuthOutcome.SESSION_IDLE_TIMEOUT,
                            "session has timed out due to inactivity");
                }
                // 关键判定：提交的凭证不等于链上当前凭证 => 旧凭证被重复使用
                if (!refreshToken.equals(chain.getCurrentRefreshToken())) {
                    sessionRepository.revoke(chain);
                    log.warn("refresh-reuse-detected sessionId={} username={} presentedPrefix={} currentPrefix={} -> chain revoked",
                            chain.getSessionId(), chain.getUsername(), prefix(refreshToken),
                            prefix(chain.getCurrentRefreshToken()));
                    auditService.record("REFRESH", chain.getUsername(), "REFRESH_TOKEN_REUSED",
                            "old refresh token reused; session chain invalidated sessionId=" + chain.getSessionId());
                    return AuthResult.failure(AuthOutcome.REFRESH_TOKEN_REUSED,
                            "old refresh token reused; the whole session chain has been invalidated");
                }

                String newRefresh = tokenIssuer.issueToken();
                boolean rotated = sessionRepository.rotateRefreshToken(chain, refreshToken, newRefresh);
                if (!rotated) {
                    // 理论上在同一监视器内不会发生；保守处理为复用，使状态收敛
                    sessionRepository.revoke(chain);
                    auditService.record("REFRESH", chain.getUsername(), "REFRESH_TOKEN_REUSED",
                            "rotation race resolved as reuse sessionId=" + chain.getSessionId());
                    return AuthResult.failure(AuthOutcome.REFRESH_TOKEN_REUSED,
                            "refresh token reuse suspected; session chain invalidated");
                }
                // 刷新即活动：推进最近活动时间
                sessionRepository.touchActivity(chain, now);

                TokenPair tokens = issueTokensForChain(chain);
                log.info("refresh-success sessionId={} username={} rotatedPrefix={}->{}",
                        chain.getSessionId(), chain.getUsername(), prefix(refreshToken), prefix(newRefresh));
                auditService.record("REFRESH", chain.getUsername(), "REFRESH_SUCCESS",
                        "token rotated sessionId=" + chain.getSessionId());
                return AuthResult.success(AuthOutcome.REFRESH_SUCCESS, tokens, "token pair rotated");
            }
        }
    }

    /** 主动撤销：凭 refresh 凭证定位会话链并整体失效。 */
    public AuthResult revoke(String refreshToken) {
        log.info("revoke-attempt refreshTokenPrefix={}", prefix(refreshToken));
        if (refreshToken == null || refreshToken.isBlank()) {
            auditService.record("REVOKE", "anonymous", "REVOKE_NOT_FOUND", "missing refresh token");
            return AuthResult.failure(AuthOutcome.REVOKE_NOT_FOUND, "refresh token is required");
        }
        Optional<SessionChain> chainOpt = sessionRepository.findByRefreshToken(refreshToken);
        if (chainOpt.isEmpty()) {
            auditService.record("REVOKE", "anonymous", "REVOKE_NOT_FOUND", "token not found prefix=" + prefix(refreshToken));
            return AuthResult.failure(AuthOutcome.REVOKE_NOT_FOUND, "unknown refresh token");
        }
        SessionChain chain = chainOpt.get();
        sessionRepository.revoke(chain);
        log.info("revoke-success sessionId={} username={}", chain.getSessionId(), chain.getUsername());
        auditService.record("REVOKE", chain.getUsername(), "REVOKE_SUCCESS",
                "session chain revoked sessionId=" + chain.getSessionId());
        return AuthResult.success(AuthOutcome.REVOKE_SUCCESS, null, "session revoked");
    }

    private TokenPair issueNewSession(String username) {
        Instant now = clock.now();
        String sessionId = UUID.randomUUID().toString();
        String refreshToken = tokenIssuer.issueToken();
        SessionChain chain = new SessionChain(
                sessionId, username, refreshToken, now.plus(refreshTtl), now, now, SessionState.ACTIVE);
        // 用户级监视器内建档 + 容量治理：计数、闲置收敛、淘汰与同用户并发刷新互不算错
        synchronized (sessionRepository.userLock(username)) {
            sessionRepository.create(chain);
            List<SessionChain> evicted = sessionRepository.evictOverflow(
                    username, now, idleTimeout, maxSessionsPerUser, sessionId);
            for (SessionChain victim : evicted) {
                log.warn("session-evicted username={} evictedSessionId={} lastActivityAt={} reason=capacity limit={}",
                        username, victim.getSessionId(), victim.getLastActivityAt(), maxSessionsPerUser);
                auditService.record("SESSION", username, "SESSION_EVICTED",
                        "capacity overflow; sessionId=" + victim.getSessionId()
                                + " lastActivityAt=" + victim.getLastActivityAt());
            }
        }
        return issueTokensForChain(chain);
    }

    private TokenPair issueTokensForChain(SessionChain chain) {
        Instant now = clock.now();
        String accessToken = tokenIssuer.issueToken();
        Instant accessExpiresAt = now.plus(accessTtl);
        AccessRecord record = new AccessRecord(
                accessToken, chain.getSessionId(), chain.getUsername(), accessExpiresAt, false);
        sessionRepository.saveAccessRecord(record);
        return new TokenPair(accessToken, chain.getCurrentRefreshToken(),
                accessExpiresAt, chain.getRefreshTokenExpiresAt());
    }

    private static String prefix(String token) {
        if (token == null || token.length() < 6) {
            return "n/a";
        }
        return token.substring(0, 6) + "…";
    }
}
