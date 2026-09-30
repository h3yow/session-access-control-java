package com.github.h3yow.sessionaccesscontroljava.session;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话与访问凭证存储（内存实现）。
 *
 * 并发语义：
 * 1. 每次 {@link #rotateRefreshToken} 在会话对象监视器内做 CAS 式比对替换，
 *    同一 refresh 凭证的并发刷新只有一个线程能看到 expected 匹配并成功，
 *    另一个线程拿到的已是新凭证，自然失败 —— 不会产生两条同时有效的链。
 * 2. 旧 refresh 凭证轮换后仍保留在凭证索引中（可解析到同一会话），但不再等于链上当前凭证；
 *    旧凭证再次出现即可被识别为"复用"，并令整条链失效。
 * 3. 撤销/淘汰/闲置会以带原因的方式级联标记其全部已签发访问凭证，拒绝原因可区分。
 *
 * 锁层级（全局固定顺序，避免死锁）：用户监视器 -> 会话监视器。
 * 登录（含容量淘汰）、刷新、定向撤销、列表惰性扫描、访问活动推进，凡涉及同一用户多条会话
 * 一致性判定的操作，都先取该用户的监视器，再在需要时进入单条会话监视器。
 */
@Component
public class SessionRepository {

    private final ConcurrentHashMap<String, SessionChain> sessionsById = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> sessionIdByRefreshToken = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AccessRecord> accessRecords = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> userLocks = new ConcurrentHashMap<>();

    public SessionChain create(SessionChain chain) {
        sessionsById.put(chain.getSessionId(), chain);
        sessionIdByRefreshToken.put(chain.getCurrentRefreshToken(), chain.getSessionId());
        return chain;
    }

    /** 同一用户名始终返回同一个监视器对象（用户串行化点）。 */
    public Object userLock(String username) {
        return userLocks.computeIfAbsent(username, k -> new Object());
    }

    public Optional<SessionChain> findByRefreshToken(String refreshToken) {
        if (refreshToken == null) {
            return Optional.empty();
        }
        String sessionId = sessionIdByRefreshToken.get(refreshToken);
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessionsById.get(sessionId));
    }

    public Optional<SessionChain> findById(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessionsById.get(sessionId));
    }

    public List<SessionChain> chainsOf(String username) {
        List<SessionChain> out = new ArrayList<>();
        for (SessionChain chain : sessionsById.values()) {
            if (chain.getUsername().equals(username)) {
                out.add(chain);
            }
        }
        return out;
    }

    /**
     * 原子轮换：仅当会话当前 refresh 凭证等于 expectedOld 时才替换为 newToken。
     * 调用方必须已持有用户监视器，并在同一临界区内完成过期/闲置/复用判定。
     */
    public boolean rotateRefreshToken(SessionChain chain, String expectedOld, String newToken) {
        synchronized (chain) {
            if (chain.getState() != SessionState.ACTIVE) {
                return false;
            }
            if (!expectedOld.equals(chain.getCurrentRefreshToken())) {
                return false;
            }
            chain.setCurrentRefreshToken(newToken);
            sessionIdByRefreshToken.put(newToken, chain.getSessionId());
            return true;
        }
    }

    /** 推进最近活动时间；仅 ACTIVE 会话生效。调用方持有用户监视器。 */
    public void touch(SessionChain chain, Instant now) {
        synchronized (chain) {
            if (chain.getState() == SessionState.ACTIVE
                    && chain.getLastActivityAt().isBefore(now)) {
                chain.setLastActivityAt(now);
            }
        }
    }

    /**
     * 惰性时间判定：ACTIVE 会话若已达绝对过期或闲置超时，则一次性收敛到对应终态，
     * 并把原因级联到该会话全部访问凭证。幂等：终态会话原样返回。
     * 调用方必须持有用户监视器。
     *
     * @return 判定后的当前状态
     */
    public SessionState settleTimeBasedState(SessionChain chain, Instant now, Duration idleTtl) {
        synchronized (chain) {
            if (chain.getState() != SessionState.ACTIVE) {
                return chain.getState();
            }
            if (!now.isBefore(chain.getRefreshTokenExpiresAt())) {
                chain.setState(SessionState.EXPIRED);
            } else if (idleTtl != null
                    && now.isAfter(chain.getLastActivityAt().plus(idleTtl))) {
                chain.setState(SessionState.IDLE_TIMEOUT);
            } else {
                return SessionState.ACTIVE;
            }
            SessionState settled = chain.getState();
            cascadeAccessRevoke(chain.getSessionId(), accessReasonFor(settled));
            return settled;
        }
    }

    /**
     * 终止一条 ACTIVE 会话（撤销/淘汰/复用），终态幂等、不可重新激活。
     * @return true 表示本次调用完成了 ACTIVE -> 终态的转换；false 表示它此前已在终态
     */
    public boolean terminate(SessionChain chain, SessionState terminalState, AccessRevokeReason accessReason) {
        synchronized (chain) {
            if (chain.getState() != SessionState.ACTIVE) {
                return false;
            }
            chain.setState(terminalState);
        }
        cascadeAccessRevoke(chain.getSessionId(), accessReason);
        return true;
    }

    /** 撤销整条会话链（兼容既有语义）；仅在 ACTIVE -> REVOKED 时级联，不覆盖其他终态原因。 */
    public void revoke(SessionChain chain) {
        terminate(chain, SessionState.REVOKED, AccessRevokeReason.SESSION_REVOKED);
    }

    public void saveAccessRecord(AccessRecord record) {
        accessRecords.put(record.getAccessToken(), record);
    }

    public Optional<AccessRecord> findAccessRecord(String accessToken) {
        if (accessToken == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(accessRecords.get(accessToken));
    }

    /** 标记撤销但保留记录，使拒绝原因可区分为 TOKEN_REVOKED 而非 UNKNOWN_TOKEN。 */
    public void revokeAccessRecordsOfSession(String sessionId) {
        cascadeAccessRevoke(sessionId, AccessRevokeReason.SESSION_REVOKED);
    }

    /** 级联写入访问凭证撤销原因；已带原因的记录不被覆盖（保留最先判定出的原因）。 */
    public void cascadeAccessRevoke(String sessionId, AccessRevokeReason reason) {
        for (AccessRecord record : accessRecords.values()) {
            if (record.getSessionId().equals(sessionId) && record.getRevokeReason() == null) {
                record.setRevokeReason(reason);
            }
        }
    }

    /** 测试辅助：列出某会话全部访问凭证记录。 */
    public List<AccessRecord> accessRecordsOfSession(String sessionId) {
        List<AccessRecord> out = new ArrayList<>();
        for (AccessRecord record : accessRecords.values()) {
            if (record.getSessionId().equals(sessionId)) {
                out.add(record);
            }
        }
        return out;
    }

    /** 终态到访问凭证级联原因的映射。 */
    public static AccessRevokeReason accessReasonFor(SessionState state) {
        return switch (state) {
            case REVOKED -> AccessRevokeReason.SESSION_REVOKED;
            case IDLE_TIMEOUT -> AccessRevokeReason.IDLE_TIMEOUT;
            case EVICTED -> AccessRevokeReason.EVICTED;
            case EXPIRED -> AccessRevokeReason.SESSION_REVOKED;
            case ACTIVE -> null;
        };
    }
}
