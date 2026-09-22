package com.github.h3yow.sessionaccesscontroljava.auth.store;

import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;
import com.github.h3yow.sessionaccesscontroljava.auth.model.SessionChain;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

/**
 * 会话链存储（内存实现）。
 * 每条链以 sessionId 为键，并为每条链分配一把锁：
 * 刷新等“读-判-写”复合操作必须在链锁内完成，保证并发下链状态一致。
 */
@Component
public class SessionStore {

    private final ConcurrentMap<String, SessionChain> sessions = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Object> sessionLocks = new ConcurrentHashMap<>();

    public void put(SessionChain chain) {
        sessions.put(chain.getSessionId(), chain);
        sessionLocks.computeIfAbsent(chain.getSessionId(), k -> new Object());
    }

    public Optional<SessionChain> find(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessions.get(sessionId));
    }

    /** 获取（不存在则创建）某条链的锁。 */
    public Object lockOf(String sessionId) {
        return sessionLocks.computeIfAbsent(sessionId, k -> new Object());
    }

    /**
     * 在某条链的锁保护下执行动作。保证同一会话链上的轮换/撤销串行化。
     */
    public <T> T withSessionLock(String sessionId, Supplier<T> action) {
        synchronized (lockOf(sessionId)) {
            return action.get();
        }
    }

    /** 撤销整条会话链。撤销幂等，原因只记录首次。 */
    public void revoke(String sessionId, DecisionReason reason, Instant now) {
        SessionChain chain = sessions.get(sessionId);
        if (chain == null) {
            return;
        }
        synchronized (lockOf(sessionId)) {
            chain.revoke(reason, now);
        }
    }
}
