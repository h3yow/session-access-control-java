package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.access.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDeniedReason;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceResult;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 绝对有效期（refresh 凭证到期）治理用例。
 *
 * 场景核心：会话的 refresh 凭证已到达绝对过期时间，但闲置窗口还没到
 * （刚还有活动），且此前签发的 access 凭证表面上也还没自然到期。
 * 此时名单 / 访问 / 刷新三个入口必须一致地把该会话视为失效：
 * - 名单：不再出现在存活列表中；
 * - 访问：拒绝，原因 SESSION_EXPIRED（区别于 TOKEN_EXPIRED / SESSION_IDLE_TIMEOUT /
 *   SESSION_REVOKED / SESSION_EVICTED）；
 * - 刷新：拒绝，原因 REFRESH_TOKEN_EXPIRED；
 * - 终态 EXPIRED 不可复活，并发下最终状态唯一收敛。
 */
class AbsoluteExpiryTests {

    private static final Logger log = LoggerFactory.getLogger(AbsoluteExpiryTests.class);

    private static final Duration IDLE = Duration.ofMinutes(30);
    private static final Duration REFRESH_TTL = Duration.ofHours(2);

    private AuthResult login(TestFixtures.Harness h, String user, String password) {
        AuthResult r = h.authService().login(user, password);
        assertEquals(AuthOutcome.LOGIN_SUCCESS, r.outcome(), "登录应成功: " + r.message());
        return r;
    }

    private static String sid(TestFixtures.Harness h, AuthResult tokens) {
        return h.sessionRepository().findByRefreshToken(tokens.tokens().refreshToken())
                .orElseThrow().getSessionId();
    }

    /**
     * 构造"绝对过期先到、闲置窗口未到"的现场：
     * - t0        登录会话 A（绝对有效期 2h，t0+2h 到期）；
     * - t0~t0+110m 周期性刷新 A 保持活跃（绝不闲置）；
     * - t0+90m    登录会话 B（观察者，绝对有效期到 t0+3h30m）；
     * - t0+110m   A 最后一次刷新：拿到新 access 凭证（自然有效期到 t0+125m），
     *             B 也刷新一次保持活跃；
     * - t0+121m   此刻：A 已绝对过期（>120m），闲置仅 11m（<30m），A 的 access 凭证
     *             自然有效期还剩 4 分钟 —— 正是要修复的漏洞窗口。
     */
    private record Scene(TestFixtures.Harness h, String aSession, String bSession,
                         String aAccess, String aRefresh, String bAccess, String bRefresh) {
    }

    private Scene expiredButNotIdleScene() {
        TestFixtures.Harness h = TestFixtures.newHarness(IDLE, 5, REFRESH_TTL);
        AuthResult a = login(h, "alice", "password123");
        String aSession = sid(h, a);

        // 周期性刷新 A 保持活跃（每 10 分钟一次，远小于 30 分钟闲置窗口）
        String aCurrentRefresh = a.tokens().refreshToken();
        AuthResult b = null;
        for (int i = 0; i < 11; i++) {
            h.clock().advance(Duration.ofMinutes(10));
            if (i == 8) { // t0+90m：观察者 B 登录
                b = login(h, "alice", "password123");
            }
            AuthResult r = h.authService().refresh(aCurrentRefresh);
            assertEquals(AuthOutcome.REFRESH_SUCCESS, r.outcome(), "A 在绝对到期前刷新应成功");
            aCurrentRefresh = r.tokens().refreshToken();
            if (i == 10) { // t0+110m：A 在绝对到期前的最后一次刷新
                a = r;
            }
        }
        assert b != null;
        String bSession = sid(h, b);
        AuthResult bRefreshed = h.authService().refresh(b.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, bRefreshed.outcome(), "B 刷新应成功");

        h.clock().advance(Duration.ofMinutes(11)); // t0+121m：A 绝对过期 1 分钟，闲置仅 11 分钟
        log.info("SCENE expired-but-not-idle: now={} aSession={} bSession={} aIdle=11m aAbsoluteExpired=1m",
                h.clock().now(), aSession, bSession);
        return new Scene(h, aSession, bSession,
                a.tokens().accessToken(), a.tokens().refreshToken(),
                bRefreshed.tokens().accessToken(), bRefreshed.tokens().refreshToken());
    }

    @Test
    void expiredSessionDisappearsFromLiveListViewedByAnotherSession() {
        Scene s = expiredButNotIdleScene();

        GovernanceResult list = s.h().governanceService().listSessions("alice", s.bSession());
        List<String> listed = list.sessions().stream().map(v -> v.sessionId()).toList();
        log.info("CASE list-after-absolute-expiry: 存活名单={}（应只剩观察者会话）", listed);

        assertEquals(List.of(s.bSession()), listed,
                "已绝对过期的会话不得出现在存活名单中，即使闲置窗口还没到");
        assertEquals(SessionState.EXPIRED,
                s.h().sessionRepository().findById(s.aSession()).orElseThrow().getState(),
                "名单收敛后该会话应进入 EXPIRED 终态");
        assertTrue(s.h().accessControlService().decide(s.bAccess(), "profile:read").allowed(),
                "观察者会话本身不受影响");
    }

    @Test
    void accessAndRefreshAreRejectedWithDistinctReasonsAfterAbsoluteExpiry() {
        Scene s = expiredButNotIdleScene();

        // access 凭证表面还没自然到期（还剩约 4 分钟），但会话已绝对过期
        Instant accessNaturalExpiry = s.h().sessionRepository()
                .findAccessRecord(s.aAccess()).orElseThrow().getExpiresAt();
        assertTrue(s.h().clock().now().isBefore(accessNaturalExpiry),
                "前置条件：access 凭证自身尚未自然到期");

        AccessDecision access = s.h().accessControlService().decide(s.aAccess(), "profile:read");
        log.info("CASE access-after-absolute-expiry: allowed={} reason={} message={}",
                access.allowed(), access.deniedReason(), access.message());
        assertFalse(access.allowed());
        assertEquals(AccessDeniedReason.SESSION_EXPIRED, access.deniedReason(),
                "会话绝对过期必须与 TOKEN_EXPIRED/SESSION_IDLE_TIMEOUT/SESSION_REVOKED/SESSION_EVICTED 区分");

        AuthResult refresh = s.h().authService().refresh(s.aRefresh());
        log.info("CASE refresh-after-absolute-expiry: outcome={}", refresh.outcome());
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, refresh.outcome());

        assertEquals(SessionState.EXPIRED,
                s.h().sessionRepository().findById(s.aSession()).orElseThrow().getState());
    }

    @Test
    void expiredSessionNeverComesBackToLife() {
        Scene s = expiredButNotIdleScene();

        // 第一次接触：访问被拒并收敛为 EXPIRED
        assertEquals(AccessDeniedReason.SESSION_EXPIRED,
                s.h().accessControlService().decide(s.aAccess(), "profile:read").deniedReason());

        // 后续任何形式的请求都不能把它变回可用：刷新、再次访问、名单、甚至治理撤销
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, s.h().authService().refresh(s.aRefresh()).outcome());
        assertEquals(AccessDeniedReason.SESSION_EXPIRED,
                s.h().accessControlService().decide(s.aAccess(), "profile:read").deniedReason());
        GovernanceResult list = s.h().governanceService().listSessions("alice", s.bSession());
        assertTrue(list.sessions().stream().noneMatch(v -> v.sessionId().equals(s.aSession())));

        // 时间继续流逝后再试，状态仍是 EXPIRED，绝无复活
        s.h().clock().advance(Duration.ofMinutes(5));
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, s.h().authService().refresh(s.aRefresh()).outcome());
        assertEquals(SessionState.EXPIRED,
                s.h().sessionRepository().findById(s.aSession()).orElseThrow().getState());
        log.info("CASE never-reactivated: 访问/刷新/名单/时间流逝后状态恒为 EXPIRED");
    }

    @Test
    void expiryBoundaryIsExactAndConsistentAcrossEntryPoints() {
        // 闲置窗口（2h）大于绝对有效期（1h），保证边界处只有绝对过期一个变量
        // 边界前一秒：三个入口都视为存活
        TestFixtures.Harness h1 = TestFixtures.newHarness(Duration.ofHours(2), 5, Duration.ofHours(1));
        AuthResult login = login(h1, "alice", "password123");
        String sessionId = sid(h1, login);
        Instant expiresAt = h1.sessionRepository().findById(sessionId).orElseThrow()
                .getRefreshTokenExpiresAt();

        h1.clock().set(expiresAt.minusSeconds(30));
        AuthResult renewed = h1.authService().refresh(login.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, renewed.outcome(), "到期前 30 秒刷新应成功");
        String freshAccess = renewed.tokens().accessToken();
        String freshRefresh = renewed.tokens().refreshToken();

        h1.clock().set(expiresAt.minusSeconds(1));
        log.info("CASE boundary-before: now=expiresAt-1s");
        assertTrue(h1.accessControlService().decide(freshAccess, "profile:read").allowed(),
                "到期前 1 秒访问应放行");
        assertEquals(1, h1.governanceService().listSessions("alice", sessionId).sessions().size(),
                "到期前 1 秒名单应包含该会话");
        assertEquals(AuthOutcome.REFRESH_SUCCESS,
                h1.authService().refresh(freshRefresh).outcome(),
                "到期前 1 秒刷新应成功");

        // 恰好到达边界：三个入口一致拒绝（now >= expiresAt 即过期）
        TestFixtures.Harness h2 = TestFixtures.newHarness(Duration.ofHours(2), 5, Duration.ofHours(1));
        AuthResult login2 = login(h2, "alice", "password123");
        String sessionId2 = sid(h2, login2);
        Instant expiresAt2 = h2.sessionRepository().findById(sessionId2).orElseThrow()
                .getRefreshTokenExpiresAt();

        h2.clock().set(expiresAt2.minusSeconds(30));
        AuthResult renewed2 = h2.authService().refresh(login2.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, renewed2.outcome());
        String freshAccess2 = renewed2.tokens().accessToken();
        String freshRefresh2 = renewed2.tokens().refreshToken();

        h2.clock().set(expiresAt2);
        AccessDecision atBoundary = h2.accessControlService().decide(freshAccess2, "profile:read");
        AuthResult refreshAtBoundary = h2.authService().refresh(freshRefresh2);
        GovernanceResult listAtBoundary = h2.governanceService().listSessions("alice", sessionId2);
        log.info("CASE boundary-exact: now=expiresAt access={} refresh={} listSize={}",
                atBoundary.deniedReason(), refreshAtBoundary.outcome(), listAtBoundary.sessions().size());

        assertEquals(AccessDeniedReason.SESSION_EXPIRED, atBoundary.deniedReason(),
                "到达绝对到期时刻访问即拒绝");
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, refreshAtBoundary.outcome(),
                "到达绝对到期时刻刷新即拒绝");
        assertEquals(0, listAtBoundary.sessions().size(), "到达绝对到期时刻名单即不含该会话");
        assertEquals(SessionState.EXPIRED,
                h2.sessionRepository().findById(sessionId2).orElseThrow().getState());
    }

    @Test
    void sessionExpiredIsDistinctFromAllOtherDenialReasons() {
        // 1) TOKEN_EXPIRED：会话存活（未闲置未过期），仅 access 凭证自然到期
        TestFixtures.Harness h = TestFixtures.newHarness(IDLE, 1, REFRESH_TTL);
        AuthResult tokenExpired = login(h, "alice", "password123");
        h.clock().advance(TestFixtures.ACCESS_TTL.plusSeconds(1)); // 15m+1s < 闲置 30m
        AccessDecision d1 = h.accessControlService().decide(tokenExpired.tokens().accessToken(), "profile:read");
        assertEquals(AccessDeniedReason.TOKEN_EXPIRED, d1.deniedReason());

        // 2) SESSION_IDLE_TIMEOUT：闲置窗口（2m）短于 access 凭证有效期（15m），
        //    保证闲置触发时 access 凭证自身仍有效，原因不会被 TOKEN_EXPIRED 掩盖
        TestFixtures.Harness hIdle = TestFixtures.newHarness(Duration.ofMinutes(2), 5, REFRESH_TTL);
        AuthResult idle = login(hIdle, "alice", "password123");
        hIdle.clock().advance(Duration.ofMinutes(2).plusSeconds(1));
        AccessDecision d2 = hIdle.accessControlService().decide(idle.tokens().accessToken(), "profile:read");
        assertEquals(AccessDeniedReason.SESSION_IDLE_TIMEOUT, d2.deniedReason());

        // 3) SESSION_EVICTED：容量上限 1，admin 两次登录淘汰第一次
        AuthResult evicted = login(h, "admin", "admin123");
        login(h, "admin", "admin123");
        AccessDecision d3 = h.accessControlService().decide(evicted.tokens().accessToken(), "profile:read");
        assertEquals(AccessDeniedReason.SESSION_EVICTED, d3.deniedReason());

        // 4) SESSION_EXPIRED：绝对有效期 20m 先于闲置（30m）到达；
        //    到期前 1 分钟刷新一次，使 access 凭证在过期时刻仍未自然到期
        TestFixtures.Harness h2 = TestFixtures.newHarness(IDLE, 5, Duration.ofMinutes(20));
        AuthResult expiredLogin = login(h2, "alice", "password123");
        h2.clock().advance(Duration.ofMinutes(19));
        AuthResult expiredRenewed = h2.authService().refresh(expiredLogin.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, expiredRenewed.outcome());
        h2.clock().advance(Duration.ofMinutes(2)); // t=21m：绝对过期 1m，闲置 2m，access 还剩 13m
        AccessDecision d4 = h2.accessControlService()
                .decide(expiredRenewed.tokens().accessToken(), "profile:read");
        assertEquals(AccessDeniedReason.SESSION_EXPIRED, d4.deniedReason());

        // 5) 主动撤销：access 被级联撤销 -> TOKEN_REVOKED，刷新 -> SESSION_REVOKED
        AuthResult revoked = login(h2, "bob", "bob123");
        h2.authService().revoke(revoked.tokens().refreshToken());
        AccessDecision d5 = h2.accessControlService().decide(revoked.tokens().accessToken(), "profile:read");
        assertEquals(AccessDeniedReason.TOKEN_REVOKED, d5.deniedReason());
        assertEquals(AuthOutcome.SESSION_REVOKED,
                h2.authService().refresh(revoked.tokens().refreshToken()).outcome());

        log.info("CASE distinct-reasons: tokenExpired={} idle={} evicted={} expired={} revoked={}",
                d1.deniedReason(), d2.deniedReason(), d3.deniedReason(), d4.deniedReason(),
                d5.deniedReason());
        assertNotEquals(d4.deniedReason(), d1.deniedReason());
        assertNotEquals(d4.deniedReason(), d2.deniedReason());
        assertNotEquals(d4.deniedReason(), d3.deniedReason());
        assertNotEquals(d4.deniedReason(), d5.deniedReason());
    }

    @Test
    void concurrentListAccessRefreshAroundExpiryConvergeToSingleState() throws Exception {
        Scene s = expiredButNotIdleScene();

        int threads = 24;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        ConcurrentLinkedQueue<String> results = new ConcurrentLinkedQueue<>();
        AtomicInteger allowedAccess = new AtomicInteger();
        AtomicInteger successfulRefresh = new AtomicInteger();
        AtomicInteger listsContainingExpired = new AtomicInteger();

        for (int i = 0; i < threads; i++) {
            final int mod = i % 3;
            pool.submit(() -> {
                try {
                    start.await();
                    if (mod == 0) {
                        AccessDecision d = s.h().accessControlService().decide(s.aAccess(), "profile:read");
                        results.add("access:" + (d.allowed() ? "ALLOWED" : d.deniedReason()));
                        if (d.allowed()) {
                            allowedAccess.incrementAndGet();
                        }
                    } else if (mod == 1) {
                        AuthResult r = s.h().authService().refresh(s.aRefresh());
                        results.add("refresh:" + r.outcome());
                        if (r.outcome() == AuthOutcome.REFRESH_SUCCESS) {
                            successfulRefresh.incrementAndGet();
                        }
                    } else {
                        GovernanceResult g = s.h().governanceService().listSessions("alice", s.bSession());
                        boolean contains = g.sessions().stream()
                                .anyMatch(v -> v.sessionId().equals(s.aSession()));
                        results.add("list:contains=" + contains);
                        if (contains) {
                            listsContainingExpired.incrementAndGet();
                        }
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

        log.info("CASE concurrent-after-expiry: results={}", results);
        log.info("CASE concurrent-after-expiry: allowedAccess={} successfulRefresh={} listsContainingExpired={}",
                allowedAccess.get(), successfulRefresh.get(), listsContainingExpired.get());

        // 同一时刻三个入口必须一致拒绝/隐藏：无任何放行、无任何成功刷新、无名单漏出
        assertEquals(0, allowedAccess.get(), "绝对过期后任何并发访问都不得放行");
        assertEquals(0, successfulRefresh.get(), "绝对过期后任何并发刷新都不得成功");
        assertEquals(0, listsContainingExpired.get(), "绝对过期后任何并发名单都不得包含该会话");
        assertTrue(results.stream().filter(r -> r.startsWith("access:"))
                .allMatch(r -> r.equals("access:" + AccessDeniedReason.SESSION_EXPIRED)),
                "所有访问拒绝原因必须统一为 SESSION_EXPIRED，实际=" + results);
        assertTrue(results.stream().filter(r -> r.startsWith("refresh:"))
                .allMatch(r -> r.equals("refresh:" + AuthOutcome.REFRESH_TOKEN_EXPIRED)),
                "所有刷新拒绝原因必须统一为 REFRESH_TOKEN_EXPIRED，实际=" + results);

        // 最终状态唯一收敛为 EXPIRED，且之后任何请求都不能复活它
        assertEquals(SessionState.EXPIRED,
                s.h().sessionRepository().findById(s.aSession()).orElseThrow().getState());
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, s.h().authService().refresh(s.aRefresh()).outcome());
        assertEquals(AccessDeniedReason.SESSION_EXPIRED,
                s.h().accessControlService().decide(s.aAccess(), "profile:read").deniedReason());
        assertEquals(SessionState.EXPIRED,
                s.h().sessionRepository().findById(s.aSession()).orElseThrow().getState());
        log.info("CASE concurrent-after-expiry: 最终状态唯一收敛 EXPIRED，无复活、无有效会话链");
    }

    @Test
    void concurrentWaveBeforeExpiryAllAllowedWaveAfterAllDenied() throws Exception {
        // 到期前一刻的并发波次：全部放行；跨过边界后的并发波次：全部一致拒绝
        TestFixtures.Harness h = TestFixtures.newHarness(Duration.ofHours(2), 5, Duration.ofHours(1));
        AuthResult login = login(h, "alice", "password123");
        String sessionId = sid(h, login);
        Instant expiresAt = h.sessionRepository().findById(sessionId).orElseThrow()
                .getRefreshTokenExpiresAt();
        h.clock().set(expiresAt.minusSeconds(30));
        AuthResult renewed = h.authService().refresh(login.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, renewed.outcome(), "到期前 30 秒刷新应成功");
        String access = renewed.tokens().accessToken();

        h.clock().set(expiresAt.minusSeconds(2));
        int wave = 12;
        AtomicInteger allowedBefore = new AtomicInteger();
        runAccessWave(h, access, wave, allowedBefore);
        log.info("CASE wave-before-expiry: allowed={}/{}", allowedBefore.get(), wave);
        assertEquals(wave, allowedBefore.get(), "到期前并发访问应全部放行");

        h.clock().set(expiresAt.plusSeconds(1));
        AtomicInteger allowedAfter = new AtomicInteger();
        runAccessWave(h, access, wave, allowedAfter);
        log.info("CASE wave-after-expiry: allowed={}/{}", allowedAfter.get(), wave);
        assertEquals(0, allowedAfter.get(), "到期后并发访问应全部拒绝");
        assertEquals(SessionState.EXPIRED,
                h.sessionRepository().findById(sessionId).orElseThrow().getState());
    }

    private void runAccessWave(TestFixtures.Harness h, String access, int threads,
                               AtomicInteger allowedCounter) throws InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    if (h.accessControlService().decide(access, "profile:read").allowed()) {
                        allowedCounter.incrementAndGet();
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
    }
}
