package com.github.h3yow.sessionaccesscontroljava.auth;

import com.github.h3yow.sessionaccesscontroljava.clock.TickClock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 连续登录失败计数与账户锁定。
 *
 * 并发语义：每个用户名持有独立监视器，同一用户的失败计数/锁定判定串行化，
 * 不同用户互不阻塞；锁定窗口过后失败计数自动清零。
 */
@Component
public class LoginFailureTracker {

    private static final Logger log = LoggerFactory.getLogger(LoginFailureTracker.class);

    private final TickClock clock;
    private final int maxFailures;
    private final Duration lockDuration;

    private final Map<String, State> states = new ConcurrentHashMap<>();

    private static final class State {
        int failures;
        Instant lockedUntil;
    }

    public LoginFailureTracker(
            TickClock clock,
            @Value("${auth.login.max-failures:5}") int maxFailures,
            @Value("${auth.login.lock-duration:PT5M}") Duration lockDuration) {
        this.clock = clock;
        this.maxFailures = maxFailures;
        this.lockDuration = lockDuration;
    }

    /**
     * 记录一次失败；达到阈值则当次立即进入锁定窗口。
     * @return 记录失败后该账户是否处于锁定状态
     */
    public boolean recordFailure(String username) {
        State state = states.computeIfAbsent(username, k -> new State());
        synchronized (state) {
            Instant now = clock.now();
            if (state.lockedUntil != null && !now.isBefore(state.lockedUntil)) {
                // 上一轮锁定已过期，重新开始计数
                state.failures = 0;
                state.lockedUntil = null;
            }
            state.failures++;
            if (state.failures >= maxFailures) {
                state.lockedUntil = now.plus(lockDuration);
                log.warn("login-failure-threshold-reached username={} failures={} lockedUntil={}",
                        username, state.failures, state.lockedUntil);
                return true;
            }
            log.info("login-failure-recorded username={} failures={}/{}",
                    username, state.failures, maxFailures);
            return false;
        }
    }

    /** 登录成功后清空计数。 */
    public void reset(String username) {
        State state = states.get(username);
        if (state == null) {
            return;
        }
        synchronized (state) {
            state.failures = 0;
            state.lockedUntil = null;
        }
        states.remove(username, state);
    }

    public boolean isLocked(String username) {
        State state = states.get(username);
        if (state == null) {
            return false;
        }
        synchronized (state) {
            if (state.lockedUntil == null) {
                return false;
            }
            if (clock.now().isBefore(state.lockedUntil)) {
                return true;
            }
            // 锁定窗口已过，清空历史计数
            state.failures = 0;
            state.lockedUntil = null;
            states.remove(username, state);
            return false;
        }
    }
}
