package com.github.h3yow.sessionaccesscontroljava.auth.store;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

/**
 * 登录失败计数存储（内存实现）。
 *
 * 失败计数与锁定状态在并发登录请求下必须一致，因此同一用户名的“读-判-写”
 * 必须在用户锁内串行完成，避免两个并发失败请求丢失计数。
 * 锁定到期后，计数与锁定在下次该用户操作时惰性清除。
 */
@Component
public class LoginFailureStore {

    /**
     * 失败计数状态：连续失败次数、锁定截止时间（null 表示未锁定）。
     */
    public record FailureState(int failureCount, Instant lockedUntil) {
        public boolean isLocked(Instant now) {
            return lockedUntil != null && now.isBefore(lockedUntil);
        }
    }

    private final ConcurrentMap<String, FailureState> states = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Object> userLocks = new ConcurrentHashMap<>();

    public <T> T withUserLock(String username, Supplier<T> action) {
        Object lock = userLocks.computeIfAbsent(username, k -> new Object());
        synchronized (lock) {
            return action.get();
        }
    }

    public Optional<FailureState> state(String username) {
        return Optional.ofNullable(states.get(username));
    }

    /** 读取状态并在锁定已到期时返回“逻辑上已清零”的快照（不落盘，由调用方决定如何更新）。 */
    public FailureState effectiveState(String username, Instant now) {
        FailureState state = states.get(username);
        if (state == null) {
            return new FailureState(0, null);
        }
        if (state.lockedUntil() != null && !now.isBefore(state.lockedUntil())) {
            return new FailureState(0, null);
        }
        return state;
    }

    public void save(String username, FailureState state) {
        states.put(username, state);
    }

    /** 登录成功后清零计数与锁定。 */
    public void reset(String username) {
        states.remove(username);
    }
}
