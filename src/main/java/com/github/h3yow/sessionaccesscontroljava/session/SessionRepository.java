package com.github.h3yow.sessionaccesscontroljava.session;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
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
 * 2. 旧 refresh 凭证轮换后进入索引仍可解析到该会话，但不再等于链上当前凭证；
 *    之后任何对旧凭证的再次使用都能被识别为"复用"，并令整条链失效。
 * 3. 撤销会话时级联撤销其全部已签发访问凭证。
 * 4. 每个用户一把用户级监视器：登录建档 + 闲置收敛 + 容量淘汰在同一把锁内原子完成；
 *    刷新先取用户锁再取会话锁（固定加锁顺序 user -> session，不会死锁），
 *    因此容量计数/淘汰不会与同一用户正在进行的刷新相互算错。
 * 5. 所有状态流转只能从 ACTIVE 进入唯一终态（{@link #transitionIfActive}），
 *    终态绝不会被重新激活；并发撤销/淘汰/闲置判定的最终状态唯一收敛为先到的终态。
 */
@Component
public class SessionRepository {

    private final ConcurrentHashMap<String, SessionChain> sessionsById = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> sessionIdByRefreshToken = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AccessRecord> accessRecords = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Object> userLocks = new ConcurrentHashMap<>();

    /** 取某用户的会话治理监视器（同用户名永远返回同一把锁）。 */
    public Object userLock(String username) {
        return userLocks.computeIfAbsent(username, k -> new Object());
    }

    public SessionChain create(SessionChain chain) {
        sessionsById.put(chain.getSessionId(), chain);
        sessionIdByRefreshToken.put(chain.getCurrentRefreshToken(), chain.getSessionId());
        return chain;
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

    /** 某用户名下的全部会话（含各终态，调用方自行按状态过滤）。 */
    public List<SessionChain> sessionsOfUser(String username) {
        List<SessionChain> out = new ArrayList<>();
        for (SessionChain chain : sessionsById.values()) {
            if (chain.getUsername().equals(username)) {
                out.add(chain);
            }
        }
        return out;
    }

    /**
     * 单向状态流转：仅当会话当前为 ACTIVE 时进入目标终态。
     * 已是终态则保留原终态不变（终态不可被重新激活、不可被覆盖），返回 false。
     * 必须在持有会话监视器时调用。
     */
    public boolean transitionIfActive(SessionChain chain, SessionState target) {
        synchronized (chain) {
            if (chain.getState() != SessionState.ACTIVE) {
                return false;
            }
            chain.setState(target);
            return true;
        }
    }

    /**
     * 闲置判定：会话处于 ACTIVE 且最近活动时间距 now 超过 idleTimeout，则收敛为 IDLE_TIMEOUT。
     * 必须在持有会话监视器时调用（或由调用方在外层持有用户锁后进入会话锁）。
     * 返回流转后的状态。
     */
    public SessionState evaluateIdle(SessionChain chain, Instant now, Duration idleTimeout) {
        synchronized (chain) {
            if (chain.getState() == SessionState.ACTIVE
                    && !chain.getLastActivityAt().plus(idleTimeout).isAfter(now)) {
                chain.setState(SessionState.IDLE_TIMEOUT);
            }
            return chain.getState();
        }
    }

    /**
     * 绝对过期判定：会话处于 ACTIVE 且刷新凭证的绝对到期时间已到（now >= refreshTokenExpiresAt），
     * 则收敛为 EXPIRED 终态。与闲置相互独立：即使刚刚还有活动，绝对到期一到即失效。
     * 必须在持有会话监视器时调用。返回流转后的状态。
     */
    public SessionState evaluateAbsoluteExpiry(SessionChain chain, Instant now) {
        synchronized (chain) {
            if (chain.getState() == SessionState.ACTIVE
                    && !now.isBefore(chain.getRefreshTokenExpiresAt())) {
                chain.setState(SessionState.EXPIRED);
            }
            return chain.getState();
        }
    }

    /**
     * 存活判定（单次加锁内原子完成）：先绝对过期、后闲置。
     * 绝对过期优先于闲置，保证"已绝对过期但闲置窗口未到"的会话收敛为 EXPIRED 而非 IDLE_TIMEOUT，
     * 使名单、访问、刷新三个入口在同一时刻看到同一个唯一状态。
     */
    public SessionState evaluateLiveness(SessionChain chain, Instant now, Duration idleTimeout) {
        synchronized (chain) {
            if (chain.getState() == SessionState.ACTIVE
                    && !now.isBefore(chain.getRefreshTokenExpiresAt())) {
                chain.setState(SessionState.EXPIRED);
            }
            if (chain.getState() == SessionState.ACTIVE
                    && !chain.getLastActivityAt().plus(idleTimeout).isAfter(now)) {
                chain.setState(SessionState.IDLE_TIMEOUT);
            }
            return chain.getState();
        }
    }

    /** 在用户锁内把该用户所有已闲置的 ACTIVE 会话一次性收敛为 IDLE_TIMEOUT。 */
    public void transitionIdleSessions(String username, Instant now, Duration idleTimeout) {
        for (SessionChain chain : sessionsOfUser(username)) {
            evaluateIdle(chain, now, idleTimeout);
        }
    }

    /** 在用户锁内把该用户所有已绝对过期的 ACTIVE 会话一次性收敛为 EXPIRED。 */
    public void transitionExpiredSessions(String username, Instant now) {
        for (SessionChain chain : sessionsOfUser(username)) {
            evaluateAbsoluteExpiry(chain, now);
        }
    }

    /** 刷新/访问成功推进最近活动时间（仅 ACTIVE 会话）。 */
    public void touchActivity(SessionChain chain, Instant now) {
        synchronized (chain) {
            if (chain.getState() == SessionState.ACTIVE) {
                chain.setLastActivityAt(now);
            }
        }
    }

    /**
     * 容量治理（调用方必须持有该用户的用户锁）：
     * 先收敛闲置会话，再统计 ACTIVE；若数量超过上限，把最久未活动的会话淘汰为 EVICTED，
     * 直到回到上限以内。protectedSessionId（通常是本次刚登录的新会话）永不被淘汰。
     * 淘汰选择以 (lastActivityAt, sessionId) 全序排序，结果稳定确定。
     * 返回被淘汰的会话列表。
     */
    public List<SessionChain> evictOverflow(String username, Instant now, Duration idleTimeout,
                                            int maxSessionsPerUser, String protectedSessionId) {
        List<SessionChain> evicted = new ArrayList<>();
        // 先收敛绝对过期、再收敛闲置：已失效会话不占活跃容量
        transitionExpiredSessions(username, now);
        transitionIdleSessions(username, now, idleTimeout);

        List<SessionChain> active = sessionsOfUser(username).stream()
                .filter(c -> c.getState() == SessionState.ACTIVE)
                .toList();
        int overflow = active.size() - maxSessionsPerUser;
        if (overflow <= 0) {
            return evicted;
        }

        List<SessionChain> candidates = active.stream()
                .filter(c -> !c.getSessionId().equals(protectedSessionId))
                .sorted(Comparator.comparing(SessionChain::getLastActivityAt)
                        .thenComparing(SessionChain::getSessionId))
                .toList();
        for (int i = 0; i < overflow && i < candidates.size(); i++) {
            SessionChain victim = candidates.get(i);
            // 淘汰不级联撤销访问凭证：访问时据会话终态判定为 SESSION_EVICTED，原因可区分
            if (transitionIfActive(victim, SessionState.EVICTED)) {
                evicted.add(victim);
            }
        }
        return evicted;
    }

    /**
     * 原子轮换：仅当会话当前 refresh 凭证等于 expectedOld 时才替换为 newToken。
     * 必须在调用方持有会话一致性语义时使用（内部已对会话对象加锁）。
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
            // 新旧凭证都保留在索引中：旧凭证仍可解析到该会话，但不再等于链上当前凭证 -> 复用可识别
            sessionIdByRefreshToken.put(newToken, chain.getSessionId());
            return true;
        }
    }

    /** 主动撤销整条会话链，并级联撤销其全部访问凭证（已在终态则保持原终态，幂等）。 */
    public void revoke(SessionChain chain) {
        boolean changed = transitionIfActive(chain, SessionState.REVOKED);
        if (changed) {
            revokeAccessRecordsOfSession(chain.getSessionId());
        }
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

    public void revokeAccessRecordsOfSession(String sessionId) {
        // 标记撤销但保留记录，使拒绝原因可区分为 REVOKED 而非 UNKNOWN
        for (AccessRecord record : accessRecords.values()) {
            if (record.getSessionId().equals(sessionId)) {
                record.setRevoked(true);
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
}
