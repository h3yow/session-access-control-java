package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.audit.AuditEvent;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 覆盖：
 * - 连续失败达到阈值后账户锁定，原因 ACCOUNT_LOCKED 与 INVALID_CREDENTIALS 可区分；
 * - 成功登录清零计数；锁定窗口过后可再次登录；
 * - 并发失败请求下计数精确、不会超计/漏计；
 * - 每次判定均产生审计记录。
 */
class LoginSuppressionTests {

    private static final Logger log = LoggerFactory.getLogger(LoginSuppressionTests.class);

    @Test
    void consecutiveFailuresLockAccountWithDistinctReason() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        for (int i = 1; i <= 4; i++) {
            AuthResult r = h.authService().login("alice", "wrong-password");
            assertEquals(AuthOutcome.INVALID_CREDENTIALS, r.outcome());
        }
        AuthResult locked = h.authService().login("alice", "wrong-password");
        log.info("CASE lock: 第5次失败 outcome={} message={}", locked.outcome(), locked.message());
        assertEquals(AuthOutcome.ACCOUNT_LOCKED, locked.outcome());

        // 即使密码正确，锁定期内仍拒绝
        AuthResult correctButLocked = h.authService().login("alice", "password123");
        assertEquals(AuthOutcome.ACCOUNT_LOCKED, correctButLocked.outcome());
        log.info("CASE lock: 锁定期内使用正确密码仍 outcome={}", correctButLocked.outcome());
    }

    @Test
    void successfulLoginResetsFailuresAndLockWindowExpires() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        for (int i = 0; i < 3; i++) {
            h.authService().login("alice", "bad");
        }
        AuthResult success = h.authService().login("alice", "password123");
        assertEquals(AuthOutcome.LOGIN_SUCCESS, success.outcome());

        // 计数已重置：再来 4 次失败不应锁定
        for (int i = 0; i < 4; i++) {
            assertEquals(AuthOutcome.INVALID_CREDENTIALS, h.authService().login("alice", "bad").outcome());
        }
        log.info("CASE reset: 成功登录后计数清零，再4次失败未锁定");

        // 触发锁定后推进时间，窗口过期可重新登录
        h.authService().login("alice", "bad"); // 第5次 -> 锁定
        assertEquals(AuthOutcome.ACCOUNT_LOCKED, h.authService().login("alice", "password123").outcome());
        h.clock().advanceSeconds(5 * 60 + 1);
        AuthResult afterWindow = h.authService().login("alice", "password123");
        assertEquals(AuthOutcome.LOGIN_SUCCESS, afterWindow.outcome());
        log.info("CASE lock-window-expiry: 推进 5m+1s 后 outcome={}", afterWindow.outcome());
    }

    @Test
    void concurrentFailuresCountExactlyOncePerRequest() throws Exception {
        TestFixtures.Harness h = TestFixtures.newHarness();
        int threads = 5;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger invalid = new AtomicInteger();
        AtomicInteger locked = new AtomicInteger();

        log.info("CASE concurrent-failures: threads={} 阈值=5", threads);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    AuthResult r = h.authService().login("alice", "bad");
                    if (r.outcome() == AuthOutcome.INVALID_CREDENTIALS) {
                        invalid.incrementAndGet();
                    } else if (r.outcome() == AuthOutcome.ACCOUNT_LOCKED) {
                        locked.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));
        log.info("CASE concurrent-failures: INVALID_CREDENTIALS={}, ACCOUNT_LOCKED={}",
                invalid.get(), locked.get());
        assertEquals(threads, invalid.get() + locked.get());
        assertEquals(4, invalid.get(), "阈值为5时，并发5次失败中恰有4次返回凭据错误");
        assertEquals(1, locked.get(), "恰有第5次触发锁定");

        // 计数一致性：之后任何请求都被锁定
        assertEquals(AuthOutcome.ACCOUNT_LOCKED, h.authService().login("alice", "bad").outcome());
    }

    @Test
    void everyDecisionIsAudited() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        h.authService().login("alice", "bad");
        h.authService().login("alice", "password123");
        h.authService().refresh("unknown");
        h.accessControlService().decide(null, "profile:read");

        long auditCount = h.auditService().snapshot().size();
        log.info("CASE audit: 审计事件数={}", auditCount);
        assertTrue(auditCount >= 4);
        for (AuditEvent event : h.auditService().snapshot()) {
            assertNotNull(event.action());
            assertNotNull(event.result());
            log.info("audit-snapshot action={} subject={} result={} detail={}",
                    event.action(), event.subject(), event.result(), event.detail());
        }
    }
}
