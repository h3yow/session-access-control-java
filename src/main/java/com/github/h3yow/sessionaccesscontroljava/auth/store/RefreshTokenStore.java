package com.github.h3yow.sessionaccesscontroljava.auth.store;

import com.github.h3yow.sessionaccesscontroljava.auth.model.RefreshTokenEntry;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

/**
 * 刷新凭证索引存储（内存实现）。
 *
 * 关键并发语义：
 * 1) 索引永久保留已轮换（REPLACED）/已撤销（REVOKED）的凭证，使旧凭证重放可被
 *    识别为 {@code REFRESH_TOKEN_REUSED}，而不是 TOKEN_UNKNOWN。
 * 2) 每个凭证哈希有一把锁，同一凭证的并发刷新在锁内串行，第一个请求完成轮换后，
 *    后到的请求看到的必然是 REPLACED 状态，从而不会产生两条同时有效的链。
 */
@Component
public class RefreshTokenStore {

    private final ConcurrentMap<String, RefreshTokenEntry> tokens = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Object> tokenLocks = new ConcurrentHashMap<>();

    public void put(RefreshTokenEntry entry) {
        tokens.put(entry.getTokenHash(), entry);
        tokenLocks.computeIfAbsent(entry.getTokenHash(), k -> new Object());
    }

    public Optional<RefreshTokenEntry> find(String tokenHash) {
        if (tokenHash == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(tokens.get(tokenHash));
    }

    /** 在某个刷新凭证的锁保护下执行动作。 */
    public <T> T withTokenLock(String tokenHash, Supplier<T> action) {
        Object lock = tokenLocks.computeIfAbsent(tokenHash, k -> new Object());
        synchronized (lock) {
            return action.get();
        }
    }
}
