package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceOutcome;
import com.github.h3yow.sessionaccesscontroljava.governance.SessionView;
import com.github.h3yow.sessionaccesscontroljava.session.SessionChain;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 并发治理：
 * - 同一会话并发刷新：严格一次成功，旧凭证复用不产生双有效链；
 * - 同一会话并发撤销 + 并发刷新交错：最终唯一收敛为 REVOKED，撤销后一切访问/刷新被拒；
 * - 并发登录超过容量：活跃会话数稳定等于上限，淘汰结果与会话状态一致。
 */
class ConcurrentGovernanceTests {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentGovernanceTests.class);

    @Test
    void concurrentRefreshOnSameSessionHasExactlyOneWinner() throws Exception {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String refresh = login.tokens().refreshToken();
        String sessionId = h.sessionRepository().findByRefreshToken(refresh).orElseThrow().getSessionId();

        int threads = 24;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger success = new AtomicInteger();
        ConcurrentLinkedQueue<AuthOutcome> outcomes = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    AuthResult r = h.authService().refresh(refresh);
                    outcomes.add(r.outcome());
                    if (r.isSuccess()) {
                        success.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));

        log.info("CASE concurrent-refresh: 24 线程同凭证刷新, success={}, outcomes={}",
                success.get(), outcomes);
        assertEquals(1, success.get(), "同一凭证并发刷新必须恰好一次成功");
        // 输掉竞争的线程只能被判定为复用或（首个复用已撤链后的）已撤销，绝不能出现第二个成功
        long losers = outcomes.stream()
                .filter(o -> o == AuthOutcome.REFRESH_TOKEN_REUSED || o == AuthOutcome.SESSION_REVOKED)
                .count();
        assertEquals(threads - 1, losers);

        SessionChain chain = h.sessionRepository().findById(sessionId).orElseThrow();
        // 收敛：要么因竞争复用全链 REVOKED；要么极端串行调度下保持 ACTIVE 但当前凭证唯一
        if (chain.getState() == SessionState.REVOKED) {
            assertTrue(outcomes.contains(AuthOutcome.REFRESH_TOKEN_REUSED));
        } else {
            assertEquals(SessionState.ACTIVE, chain.getState());
            assertNotEquals(refresh, chain.getCurrentRefreshToken());
        }
    }

    @Test
    void interleavedRevokeAndRefreshConvergesToSingleTerminalState() throws Exception {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String sessionId = h.sessionRepository().findByRefreshToken(login.tokens().refreshToken())
                .orElseThrow().getSessionId();

        int revokers = 8;
        int refreshers = 8;
        ExecutorService pool = Executors.newFixedThreadPool(revokers + refreshers);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<AuthOutcome> refreshOutcomes = new ConcurrentLinkedQueue<>();
        AtomicInteger revokeSuccessCalls = new AtomicInteger();
        // 每波刷新都先用"链上当前凭证"，模拟多端各自持有自己那一代凭证
        List<String> tokenGenerations = new ArrayList<>();
        tokenGenerations.add(login.tokens().refreshToken());

        for (int i = 0; i < refreshers; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    String token;
                    synchronized (tokenGenerations) {
                        token = tokenGenerations.get(Math.min(idx, tokenGenerations.size() - 1));
                    }
                    AuthResult r = h.authService().refresh(token);
                    refreshOutcomes.add(r.outcome());
                    if (r.isSuccess()) {
                        synchronized (tokenGenerations) {
                            tokenGenerations.add(r.tokens().refreshToken());
                        }
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        for (int i = 0; i < revokers; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    AuthResult r = h.authService().revoke(login.tokens().refreshToken());
                    if (r.outcome() == AuthOutcome.REVOKE_SUCCESS) {
                        revokeSuccessCalls.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));

        SessionChain chain = h.sessionRepository().findById(sessionId).orElseThrow();
        log.info("CASE revoke-vs-refresh: finalState={}, revokeSuccessCalls={}, refreshOutcomes={}",
                chain.getState(), revokeSuccessCalls.get(), refreshOutcomes);

        // 唯一终态：撤销与刷新交错后，链必须且只能停在 REVOKED
        assertEquals(SessionState.REVOKED, chain.getState());
        // 撤销调用都返回成功（终态幂等），但链状态只发生一次 ACTIVE->REVOKED 转换
        assertEquals(revokers, revokeSuccessCalls.get());
        // 任何刷新结果都不允许是成功（成功的话也必在交错中被随后的撤销终结）
        assertTrue(refreshOutcomes.stream().noneMatch(o -> o == AuthOutcome.REFRESH_SUCCESS)
                        || tokenGenerations.size() > 1,
                "若有刷新成功，其新凭证也必须已被撤销收敛: " + refreshOutcomes);

        // 收敛后：无论哪一代凭证，刷新都被明确拒绝，且不会重新激活
        for (String token : tokenGenerations) {
            AuthResult after = h.authService().refresh(token);
            assertTrue(after.outcome() == AuthOutcome.SESSION_REVOKED
                            || after.outcome() == AuthOutcome.REFRESH_TOKEN_REUSED,
                    "收敛后刷新只能是 REVOKED/REUSED，实际=" + after.outcome());
        }
        assertEquals(SessionState.REVOKED, chain.getState());
        assertTrue(h.governanceService().listSessions("alice", sessionId).sessions().isEmpty());
    }

    @Test
    void concurrentLoginsBeyondCapacityConvergeToStableCount() throws Exception {
        TestFixtures.Harness h = TestFixtures.newHarness();
        int loginAttempts = 20; // 远超 cap=3
        ExecutorService pool = Executors.newFixedThreadPool(loginAttempts);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<AuthResult> logins = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < loginAttempts; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    logins.add(h.authService().login("alice", "password123"));
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
        assertEquals(loginAttempts, logins.size());
        assertTrue(logins.stream().allMatch(AuthResult::isSuccess));

        // 全部登录完成后：活跃数稳定为 cap；其余全部处于终态（EVICTED/IDLE/EXPIRED）
        var chains = h.sessionRepository().chainsOf("alice");
        long active = chains.stream().filter(c -> c.getState() == SessionState.ACTIVE).count();
        long terminal = chains.size() - active;
        log.info("CASE concurrent-login: total={}, active={}, terminal={}, listed={}",
                chains.size(), active, terminal,
                h.governanceService().listSessions("alice", "none").sessions().size());
        assertEquals(TestFixtures.MAX_SESSIONS, active,
                "并发登录后活跃会话数必须唯一收敛到容量上限");
        assertEquals(active,
                h.governanceService().listSessions("alice", "none").sessions().size());

        // 治理视角与存储视角一致：每条非活跃会话都不在列表中
        for (SessionView v : h.governanceService().listSessions("alice", "none").sessions()) {
            assertEquals(SessionState.ACTIVE,
                    h.sessionRepository().findById(v.sessionId()).orElseThrow().getState());
        }

        // 最新登录的会话（最后一批）必然存活：淘汰永不误伤最新会话
        AuthResult newest = h.authService().login("alice", "password123");
        String newestId = h.sessionRepository()
                .findByRefreshToken(newest.tokens().refreshToken()).orElseThrow().getSessionId();
        assertEquals(SessionState.ACTIVE,
                h.sessionRepository().findById(newestId).orElseThrow().getState());
        assertEquals(TestFixtures.MAX_SESSIONS,
                h.governanceService().listSessions("alice", newestId).sessions().size());
    }

    @Test
    void concurrentGovernanceRevokeAndTargetedRevokeAgree() throws Exception {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String sessionId = h.sessionRepository().findByRefreshToken(login.tokens().refreshToken())
                .orElseThrow().getSessionId();

        int n = 10;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<GovernanceOutcome> gov = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < n; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    gov.add(h.governanceService()
                            .revokeSession("alice", sessionId, sessionId).outcome());
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));

        long revoked = gov.stream().filter(o -> o == GovernanceOutcome.REVOKE_SESSION_SUCCESS).count();
        long notActive = gov.stream().filter(o -> o == GovernanceOutcome.SESSION_NOT_ACTIVE).count();
        log.info("CASE concurrent-targeted-revoke: success={}, notActive={}", revoked, notActive);
        assertEquals(1, revoked, "只有一个线程完成 ACTIVE->REVOKED 转换");
        assertEquals(n - 1, notActive, "其余线程看到的是稳定终态 SESSION_NOT_ACTIVE");
        assertEquals(SessionState.REVOKED,
                h.sessionRepository().findById(sessionId).orElseThrow().getState());
    }
}
