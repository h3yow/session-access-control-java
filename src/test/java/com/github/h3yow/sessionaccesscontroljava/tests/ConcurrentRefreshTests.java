package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 同一 refresh 凭证被多线程并发刷新：
 * - 恰好一次成功；
 * - 其余请求要么未成功；一旦有旧凭证竞争方被识别复用，则整条链失效（最终状态必须一致收敛）；
 * - 绝不会出现两条同时有效的链/两个都成功的结果。
 */
class ConcurrentRefreshTests {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRefreshTests.class);

    @Test
    void concurrentRefreshOfSameTokenHasSingleWinner() throws Exception {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String refreshToken = login.tokens().refreshToken();

        int threads = 24;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<AuthOutcome> outcomes = new ConcurrentLinkedQueue<>();
        AtomicInteger success = new AtomicInteger();

        log.info("CASE concurrent-refresh: threads={} inputRefreshPrefix={}",
                threads, refreshToken.substring(0, 6));
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    AuthResult result = h.authService().refresh(refreshToken);
                    outcomes.add(result.outcome());
                    if (result.outcome() == AuthOutcome.REFRESH_SUCCESS) {
                        success.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        log.info("CASE concurrent-refresh: outcomes={}", outcomes);
        assertEquals(1, success.get(), "并发刷新只允许一个线程成功，实际成功数=" + success.get());

        long reused = outcomes.stream().filter(o -> o == AuthOutcome.REFRESH_TOKEN_REUSED).count();
        long revoked = outcomes.stream().filter(o -> o == AuthOutcome.SESSION_REVOKED).count();
        long losers = reused + revoked;
        assertEquals(threads - 1, losers, "其余线程必须全部被判定为复用/已撤销");
        log.info("CASE concurrent-refresh: 成功=1, REUSED={}, SESSION_REVOKED={}, 无双链", reused, revoked);

        // 最终状态收敛：若发生复用识别，链必须为 REVOKED；若极端调度下只有一个赢家、
        // 其他竞争线程在轮换前串行失败，则链仍 ACTIVE 且只有唯一新凭证可用。
        var chain = h.sessionRepository().findByRefreshToken(refreshToken).orElseThrow();
        if (chain.getState() == SessionState.REVOKED) {
            log.info("CASE concurrent-refresh: 状态收敛为 REVOKED（检测到竞争复用）");
        } else {
            assertEquals(SessionState.ACTIVE, chain.getState());
            assertNotEquals(refreshToken, chain.getCurrentRefreshToken());
            log.info("CASE concurrent-refresh: 状态保持 ACTIVE，唯一当前凭证 prefix={}",
                    chain.getCurrentRefreshToken().substring(0, 6));
        }
    }

    @Test
    void sequentialParallelWavesConverge() throws Exception {
        // 两波刷新：第一波赢家拿到新凭证，第二波全部用旧凭证 -> 复用 -> 链撤销
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String oldToken = login.tokens().refreshToken();

        AuthResult firstWave = h.authService().refresh(oldToken);
        assertEquals(AuthOutcome.REFRESH_SUCCESS, firstWave.outcome());

        int threads = 8;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<AuthOutcome> outcomes = new java.util.concurrent.CopyOnWriteArrayList<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    outcomes.add(h.authService().refresh(oldToken).outcome());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        long reused = outcomes.stream().filter(o -> o == AuthOutcome.REFRESH_TOKEN_REUSED).count();
        assertTrue(reused >= 1, "至少一个请求应判定 REUSED，实际=" + outcomes);
        var chain = h.sessionRepository().findByRefreshToken(firstWave.tokens().refreshToken()).orElseThrow();
        assertEquals(SessionState.REVOKED, chain.getState());
        log.info("CASE second-wave: outcomes={} 链状态=REVOKED，状态收敛", outcomes);
    }
}
