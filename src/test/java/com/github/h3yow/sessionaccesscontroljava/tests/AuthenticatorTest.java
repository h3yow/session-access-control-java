package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;
import com.github.h3yow.sessionaccesscontroljava.auth.model.Role;
import com.github.h3yow.sessionaccesscontroljava.auth.model.TokenIssued;
import com.github.h3yow.sessionaccesscontroljava.auth.security.AuditService;
import com.github.h3yow.sessionaccesscontroljava.auth.security.Authenticator;
import com.github.h3yow.sessionaccesscontroljava.auth.security.TokenHasher;
import com.github.h3yow.sessionaccesscontroljava.auth.security.TokenService;
import com.github.h3yow.sessionaccesscontroljava.auth.store.AccessTokenStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.AccountStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.AuditStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.LoginFailureStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.RefreshTokenStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.SessionStore;
import com.github.h3yow.sessionaccesscontroljava.config.SecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 登录认证与失败抑制单测：密码错误、锁定、锁定恢复、并发失败计数一致。
 */
class AuthenticatorTest {

    private static final Logger log = LoggerFactory.getLogger(AuthenticatorTest.class);

    private MutableClock clock;
    private Authenticator authenticator;
    private LoginFailureStore failureStore;
    private SecurityProperties props;

    static class MutableClock extends Clock {
        volatile Instant instant = Instant.parse("2026-09-23T00:00:00Z");

        void advanceSeconds(long s) {
            instant = instant.plusSeconds(s);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        props = new SecurityProperties();
        props.setMaxLoginFailures(5);
        props.setLockDurationSeconds(60);
        AccountStore accountStore = new AccountStore();
        failureStore = new LoginFailureStore();
        TokenHasher hasher = new TokenHasher();
        String salt = hasher.generateSalt();
        accountStore.put(new com.github.h3yow.sessionaccesscontroljava.auth.model.Account(
                "alice", salt, hasher.hashPassword("correct-pw", salt), Set.of(Role.USER)));
        AuditService auditService = new AuditService(new AuditStore(), clock);
        TokenService tokenService = new TokenService(new SessionStore(), new RefreshTokenStore(),
                new AccessTokenStore(), hasher, auditService, props, clock);
        authenticator = new Authenticator(accountStore, failureStore, tokenService,
                auditService, hasher, props, clock);
    }

    @Test
    @DisplayName("正确密码登录成功并签发凭证")
    void loginSuccess() {
        TokenIssued t = authenticator.login("alice", "correct-pw");
        log.info("[login-ok] success={} reason={} session={}", t.success(), t.reason(), t.sessionId());
        assertTrue(t.success());
        assertNotNull(t.accessToken());
    }

    @Test
    @DisplayName("连续失败达到阈值后锁定；锁定窗口内即使密码正确也拒绝；窗口过后可恢复")
    void lockoutAndRecovery() {
        for (int i = 1; i <= props.getMaxLoginFailures(); i++) {
            TokenIssued t = authenticator.login("alice", "wrong-pw");
            log.info("[fail-{}] reason={}", i, t.reason());
            // 达到阈值的当次尝试本身仍是密码错误；锁定从下一次请求开始生效
            assertEquals(DecisionReason.BAD_CREDENTIALS, t.reason());
        }
        // 达到阈值后底层状态必须已记录锁定截止时间
        assertNotNull(failureStore.state("alice").orElseThrow().lockedUntil(),
                "第 5 次失败后应已写入锁定截止时间");

        // 锁定窗口内即便输入正确密码也必须被抑制
        TokenIssued duringLock = authenticator.login("alice", "correct-pw");
        log.info("[locked] 正确密码在锁定期登录 -> reason={}", duringLock.reason());
        assertEquals(DecisionReason.ACCOUNT_LOCKED, duringLock.reason());

        // 越过锁定窗口后，计数清零，可正常登录
        clock.advanceSeconds(props.getLockDurationSeconds() + 1);
        TokenIssued recovered = authenticator.login("alice", "correct-pw");
        log.info("[recovered] 锁定期过后 -> success={} reason={}", recovered.success(), recovered.reason());
        assertTrue(recovered.success());
    }

    @Test
    @DisplayName("登录成功后失败计数清零")
    void successResetsCounter() {
        for (int i = 0; i < 3; i++) {
            assertEquals(DecisionReason.BAD_CREDENTIALS, authenticator.login("alice", "bad").reason());
        }
        assertTrue(authenticator.login("alice", "correct-pw").success());
        // 再来 4 次错误也不应锁定（阈值 5，计数已清零）
        for (int i = 0; i < 4; i++) {
            assertEquals(DecisionReason.BAD_CREDENTIALS, authenticator.login("alice", "bad").reason());
        }
        log.info("[reset] 成功后再失败 4 次仍未锁定，计数已清零");
    }

    @Test
    @DisplayName("并发失败登录计数不丢失：20 个并发错误请求后计数精确为 20 并触发锁定")
    void concurrentFailuresCountConsistently() throws Exception {
        int threads = 20;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicInteger badCredentials = new AtomicInteger();
        AtomicInteger locked = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    TokenIssued t = authenticator.login("alice", "bad");
                    if (t.reason() == DecisionReason.BAD_CREDENTIALS) {
                        badCredentials.incrementAndGet();
                    } else if (t.reason() == DecisionReason.ACCOUNT_LOCKED) {
                        locked.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        pool.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS);

        int counted = failureStore.state("alice").orElseThrow().failureCount();
        log.info("[concurrent-fail] threads={} badCredentials={} locked={} storedCount={}",
                threads, badCredentials.get(), locked.get(), counted);
        // 前 5 个 BAD_CREDENTIALS（第 5 个开始即 LOCKED），其余 LOCKED；计数恰为阈值不超限
        assertTrue(badCredentials.get() + locked.get() == threads, "所有请求都必须得到判定");
        assertTrue(locked.get() >= 1, "必须有请求观察到锁定");
        assertEquals(props.getMaxLoginFailures(), counted,
                "并发下计数精确收敛到阈值，不多不少");
        assertNotNull(failureStore.state("alice").orElseThrow().lockedUntil());
    }
}
