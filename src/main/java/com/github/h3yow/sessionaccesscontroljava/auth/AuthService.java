package com.github.h3yow.sessionaccesscontroljava.auth;

import com.github.h3yow.sessionaccesscontroljava.audit.AuditService;
import com.github.h3yow.sessionaccesscontroljava.clock.TickClock;
import com.github.h3yow.sessionaccesscontroljava.session.AccessRecord;
import com.github.h3yow.sessionaccesscontroljava.session.AccessRevokeReason;
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
import java.util.Optional;
import java.util.UUID;

/**
 * 认证服务：登录签发凭证、刷新轮换（含复用检测）、主动撤销。
 *
 * 刷新并发与复用语义：
 * - 刷新先取"用户监视器"（锁层级：用户 -> 会话），再在会话监视器内 CAS 完成轮换，
 *   同一 refresh 凭证并发刷新严格只有一次成功。
 * - 旧凭证轮换后保留可解析索引，但不再是链上当前凭证；旧凭证再次出现即判定 REUSED，
 *   整条会话链（含所有访问凭证）立即失效。
 *
 * 会话治理语义：
 * - 闲置超时与容量淘汰以"最近活动时间"为准；刷新成功推进活动时间。
 * - 登录在用户监视器内惰性扫描终态并在超过容量上限时淘汰最久未活动的另一条会话，
 *   绝不会淘汰本次新登录的会话。
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
    private final Duration idleTtl;
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
                       @Value("${auth.session.idle-ttl:PT30M}") Duration idleTtl,
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
        this.idleTtl = idleTtl;
        this.maxSessionsPerUser = maxSessionsPerUser;
    }

    /** 登录：校验锁定状态与口令，成功则签发一条新会话链与凭证对，并执行容量治理。 */
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
        log.info("login-success username={} sessionCount(cap={}) accessExpiresAt={} refreshExpiresAt={}",
                username, maxSessionsPerUser, tokens.accessTokenExpiresAt(), tokens.refreshTokenExpiresAt());
        auditService.record("LOGIN", username, "LOGIN_SUCCESS", "tokens issued");
        return AuthResult.success(AuthOutcome.LOGIN_SUCCESS, tokens, "login successful");
    }

    /**
     * 刷新：校验存在性/状态/过期，原子轮换；检测到旧凭证复用则整条链失效。
     * 全部判定在"用户监视器 -> 会话监视器"内完成，与并发登录淘汰、并发撤销、并发刷新互斥。
     */
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
        synchronized (sessionRepository.userLock(chain.getUsername())) {
            synchronized (chain) {
                // 惰性收敛时间终态：绝对过期优先于闲置，二者在刷新侧分别表现为
                // REFRESH_TOKEN_EXPIRED 与 SESSION_IDLE，语义可区分。
                SessionState settled = sessionRepository.settleTimeBasedState(chain, clock.now(), idleTtl);
                AuthOutcome terminal = switch (settled) {
                    case ACTIVE -> null;
                    case REVOKED -> AuthOutcome.SESSION_REVOKED;
                    case IDLE_TIMEOUT -> AuthOutcome.SESSION_IDLE;
                    case EVICTED -> AuthOutcome.SESSION_EVICTED;
                    case EXPIRED -> AuthOutcome.REFRESH_TOKEN_EXPIRED;
                };
                if (terminal != null) {
                    return denyRefreshForTerminal(chain, terminal);
                }
                // 关键判定：提交的凭证不等于链上当前凭证 => 旧凭证被重复使用
                if (!refreshToken.equals(chain.getCurrentRefreshToken())) {
                    sessionRepository.terminate(chain, SessionState.REVOKED, AccessRevokeReason.SESSION_REVOKED);
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
                    sessionRepository.terminate(chain, SessionState.REVOKED, AccessRevokeReason.SESSION_REVOKED);
                    auditService.record("REFRESH", chain.getUsername(), "REFRESH_TOKEN_REUSED",
                            "rotation race resolved as reuse sessionId=" + chain.getSessionId());
                    return AuthResult.failure(AuthOutcome.REFRESH_TOKEN_REUSED,
                            "refresh token reuse suspected; session chain invalidated");
                }

                TokenPair tokens = issueTokensForChain(chain);
                // 刷新成功 = 一次活动
                sessionRepository.touch(chain, clock.now());
                log.info("refresh-success sessionId={} username={} rotatedPrefix={}->{} lastActivityAt={}",
                        chain.getSessionId(), chain.getUsername(), prefix(refreshToken), prefix(newRefresh),
                        chain.getLastActivityAt());
                auditService.record("REFRESH", chain.getUsername(), "REFRESH_SUCCESS",
                        "token rotated sessionId=" + chain.getSessionId());
                return AuthResult.success(AuthOutcome.REFRESH_SUCCESS, tokens, "token pair rotated");
            }
        }
    }

    /** 主动撤销：凭 refresh 凭证定位会话链并整体失效（终态幂等：撤销已终态会话也算成功收敛）。 */
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
        synchronized (sessionRepository.userLock(chain.getUsername())) {
            boolean changed = sessionRepository.terminate(
                    chain, SessionState.REVOKED, AccessRevokeReason.SESSION_REVOKED);
            log.info("revoke-success sessionId={} username={} stateChanged={}",
                    chain.getSessionId(), chain.getUsername(), changed);
        }
        auditService.record("REVOKE", chain.getUsername(), "REVOKE_SUCCESS",
                "session chain revoked sessionId=" + chain.getSessionId());
        return AuthResult.success(AuthOutcome.REVOKE_SUCCESS, null, "session revoked");
    }

    private TokenPair issueNewSession(String username) {
        Instant now = clock.now();
        String sessionId = UUID.randomUUID().toString();
        String refreshToken = tokenIssuer.issueToken();
        SessionChain chain = new SessionChain(
                sessionId, username, refreshToken, now.plus(refreshTtl), SessionState.ACTIVE, now, now);
        // 容量治理与登录在同一用户临界区内：稳定计数、稳定淘汰、绝不淘汰新会话
        synchronized (sessionRepository.userLock(username)) {
            sessionRepository.create(chain);
            evictExcessSessions(username, chain.getSessionId(), now);
        }
        return issueTokensForChain(chain);
    }

    /**
     * 超过容量上限时，惰性收敛闲置/过期会话后，淘汰"最久未活动"的活跃会话。
     * 本次新登录的会话（excludeSessionId）永不参与淘汰。
     */
    private void evictExcessSessions(String username, String excludeSessionId, Instant now) {
        var active = new java.util.ArrayList<SessionChain>();
        for (SessionChain other : sessionRepository.chainsOf(username)) {
            SessionState state = sessionRepository.settleTimeBasedState(other, now, idleTtl);
            if (state == SessionState.ACTIVE && !other.getSessionId().equals(excludeSessionId)) {
                active.add(other);
            }
        }
        // 当前新会话必然 ACTIVE，计数含它
        int totalActive = active.size() + 1;
        int toEvict = totalActive - maxSessionsPerUser;
        if (toEvict <= 0) {
            return;
        }
        // 最久未活动优先；lastActivityAt 相同则按 sessionId 稳定排序，淘汰结果唯一
        active.sort((a, b) -> {
            int byActivity = a.getLastActivityAt().compareTo(b.getLastActivityAt());
            return byActivity != 0 ? byActivity : a.getSessionId().compareTo(b.getSessionId());
        });
        for (int i = 0; i < toEvict; i++) {
            SessionChain victim = active.get(i);
            sessionRepository.terminate(victim, SessionState.EVICTED, AccessRevokeReason.EVICTED);
            log.warn("session-evicted username={} victimSessionId={} lastActivityAt={} cap={}",
                    username, victim.getSessionId(), victim.getLastActivityAt(), maxSessionsPerUser);
            auditService.record("SESSION_GOVERNANCE", username, "SESSION_EVICTED",
                    "capacity limit reached; evicted sessionId=" + victim.getSessionId()
                            + " lastActivityAt=" + victim.getLastActivityAt());
        }
    }

    /** 已处终态（含惰性收敛出来的终态）-> 对应刷新拒绝原因；ACTIVE -> null。 */
    private AuthResult denyRefreshForTerminal(SessionChain chain, AuthOutcome outcome) {
        log.warn("refresh-denied sessionId={} username={} reason={} state={}",
                chain.getSessionId(), chain.getUsername(), outcome, chain.getState());
        auditService.record("REFRESH", chain.getUsername(), outcome.name(),
                "session not active sessionId=" + chain.getSessionId() + " state=" + chain.getState());
        String message = switch (outcome) {
            case SESSION_REVOKED -> "session has been revoked";
            case SESSION_IDLE -> "session has been invalidated due to inactivity";
            case SESSION_EVICTED -> "session has been evicted due to the active-session limit";
            case REFRESH_TOKEN_EXPIRED -> "refresh token has expired (absolute expiry)";
            default -> "session is not active";
        };
        return AuthResult.failure(outcome, message);
    }

    private TokenPair issueTokensForChain(SessionChain chain) {
        Instant now = clock.now();
        String accessToken = tokenIssuer.issueToken();
        Instant accessExpiresAt = now.plus(accessTtl);
        AccessRecord record = new AccessRecord(
                accessToken, chain.getSessionId(), chain.getUsername(), accessExpiresAt, (AccessRevokeReason) null);
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
