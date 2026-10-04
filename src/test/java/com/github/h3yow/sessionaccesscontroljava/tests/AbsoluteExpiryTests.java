package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.access.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDeniedReason;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceOutcome;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceResult;
import com.github.h3yow.sessionaccesscontroljava.session.AccessRecord;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 绝对有效期专项：长期登录凭证（会话链 refresh 凭证）到点，但闲置窗口还没到时——
 * - 名单不得再显示该会话（从另一条仍有效会话视角同样不可见）；
 * - 访问与刷新都必须拒绝，且原因与"访问凭证自身过期/闲置/撤销/淘汰"清楚区分；
 * - 进入 EXPIRED 终态后任何请求都不能将其复活；
 * - 到期边界、到期点的并发名单/访问/刷新结果唯一收敛，不出现放行/拒绝并存。
 */
@DisplayName("绝对有效期治理：绝对过期在名单/访问/刷新中的一致语义")
class AbsoluteExpiryTests {

    private static final Logger log = LoggerFactory.getLogger(AbsoluteExpiryTests.class);

    // 专项时钟布局：访问凭证 15 分钟、长期凭证绝对有效期 1 小时、闲置窗口 30 分钟。
    private static final Duration ACCESS_TTL = Duration.ofMinutes(15);
    private static final Duration REFRESH_TTL = Duration.ofHours(1);
    private static final Duration IDLE_TIMEOUT = Duration.ofMinutes(30);

    private TestFixtures.Harness newHarness() {
        return TestFixtures.newHarness(ACCESS_TTL, REFRESH_TTL, IDLE_TIMEOUT, 5);
    }

    private AuthResult login(TestFixtures.Harness h, String user, String password) {
        AuthResult r = h.authService().login(user, password);
        assertEquals(AuthOutcome.LOGIN_SUCCESS, r.outcome(), "登录应成功: " + r.message());
        return r;
    }

    private String sid(TestFixtures.Harness h, AuthResult r) {
        return h.sessionRepository().findByRefreshToken(r.tokens().refreshToken()).orElseThrow().getSessionId();
    }

    /**
     * 构造"绝对有效期先到、闲置窗口还没到"的关键局面（时间线）：
     * t=0   登录，绝对到期点 = 60m；
     * t=20m 刷新（成功），随后用新访问凭证访问一次以推进活动；
     * t=25m 再访问一次（推进活动到 25m）；
     * t=50m 刷新（距上次活动 25m < 闲置窗口 30m）成功，签发的访问凭证 65m 才自然到期；
     * t=55m 另一台设备登录（绝对到期点 115m），作为仍有效的名单观察视角；
     * t=60m 到达绝对到期点：距上次活动仅 10m（闲置未到），而那张访问凭证表面 65m 才到期。
     */
    private record ExpiredSetup(TestFixtures.Harness h,
                                AuthResult firstLogin,
                                AuthResult lastRefresh,
                                String expiredSessionId,
                                AuthResult viewer,
                                String viewerSessionId) {
    }

    private ExpiredSetup setupAtAbsoluteExpiry() {
        TestFixtures.Harness h = newHarness();
        AuthResult firstLogin = login(h, "alice", "password123"); // t=0
        String expiredId = sid(h, firstLogin);

        h.clock().advance(Duration.ofMinutes(20));
        AuthResult r20 = h.authService().refresh(firstLogin.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, r20.outcome(), "t=20m 刷新应成功");
        assertTrue(h.accessControlService().decide(r20.tokens().accessToken(), "profile:read").allowed());

        h.clock().advance(Duration.ofMinutes(5)); // t=25m
        assertTrue(h.accessControlService().decide(r20.tokens().accessToken(), "profile:read").allowed());

        h.clock().advance(Duration.ofMinutes(25)); // t=50m（距上次活动 25m，闲置窗口 30m 未到）
        AuthResult lastRefresh = h.authService().refresh(r20.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, lastRefresh.outcome(), "到期前刷新应成功");

        h.clock().advance(Duration.ofMinutes(5)); // t=55m
        AuthResult viewer = login(h, "alice", "password123");
        String viewerId = sid(h, viewer);

        h.clock().advance(Duration.ofMinutes(5)); // t=60m：绝对到期点，闲置窗口还差 20m
        return new ExpiredSetup(h, firstLogin, lastRefresh, expiredId, viewer, viewerId);
    }

    @Test
    @DisplayName("绝对过期后该会话从存活名单消失（从另一条有效会话视角同样不可见）")
    void absolutelyExpiredSessionVanishesFromLiveListWhileIdleWindowOpen() {
        ExpiredSetup s = setupAtAbsoluteExpiry();

        GovernanceResult list = s.h.governanceService()
                .listSessions("alice", s.viewerSessionId());
        assertEquals(GovernanceOutcome.SESSIONS_LISTED, list.outcome());
        List<String> ids = list.sessions().stream().map(v -> v.sessionId()).toList();
        log.info("[绝对过期-名单] t=60m 存活名单={}（不应含过期会话 {}）", ids, s.expiredSessionId());
        assertEquals(1, ids.size(), "绝对过期会话不得出现在存活名单，仅观察者会话存活");
        assertFalse(ids.contains(s.expiredSessionId()), "绝对过期会话不得出现在存活名单");
        assertEquals(s.viewerSessionId, ids.get(0));

        // 会话对象已经收敛为 EXPIRED 终态，而非仍停留在 ACTIVE
        SessionState state = s.h.sessionRepository().findById(s.expiredSessionId).orElseThrow().getState();
        assertEquals(SessionState.EXPIRED, state);
        log.info("[绝对过期-名单] 过期会话状态唯一收敛为 EXPIRED");
    }

    @Test
    @DisplayName("绝对过期后访问/刷新均被拒，原因与访问凭证自身过期、闲置、撤销、淘汰可区分")
    void accessAndRefreshAreDeniedWithDistinctReasons() {
        ExpiredSetup s = setupAtAbsoluteExpiry();
        String stillSurfaceValidAccess = s.lastRefresh.tokens().accessToken();

        // 该访问凭证表面尚未自然到期，且未被级联撤销（结构上保证原因不会被混淆为 TOKEN_REVOKED）
        AccessRecord record = s.h.sessionRepository().findAccessRecord(stillSurfaceValidAccess).orElseThrow();
        assertFalse(record.isRevoked(), "绝对过期不级联撤销访问凭证，拒绝原因须来自会话终态");
        assertTrue(s.h.clock().now().isBefore(record.getExpiresAt()),
                "前置条件：此刻访问凭证表面尚未自然到期");

        // 访问被拒：SESSION_EXPIRED（区别于 TOKEN_EXPIRED / SESSION_IDLE_TIMEOUT /
        // TOKEN_REVOKED/SESSION_REVOKED / SESSION_EVICTED）
        AccessDecision access = s.h.accessControlService().decide(stillSurfaceValidAccess, "profile:read");
        assertFalse(access.allowed());
        assertEquals(AccessDeniedReason.SESSION_EXPIRED, access.deniedReason());
        log.info("[绝对过期-访问] 表面未到期的访问凭证被拒 reason={} message={}",
                access.deniedReason(), access.message());

        // 当前 refresh 凭证刷新被拒：REFRESH_TOKEN_EXPIRED（区别于 SESSION_IDLE_TIMEOUT /
        // SESSION_REVOKED / SESSION_EVICTED / REUSED / UNKNOWN）
        AuthResult refreshCurrent = s.h.authService().refresh(s.lastRefresh.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, refreshCurrent.outcome());
        // 最初登录签发的旧 refresh 凭证同样被拒，且不会被误判为复用
        AuthResult refreshOriginal = s.h.authService().refresh(s.firstLogin.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, refreshOriginal.outcome());
        log.info("[绝对过期-刷新] 当前/旧 refresh 凭证均被拒 outcome=REFRESH_TOKEN_EXPIRED（非 REUSED）");

        // 同一张访问凭证在其自然到期之后再访问，原因切换为 TOKEN_EXPIRED —— 两种"过期"可清楚区分
        s.h.clock().advance(Duration.ofMinutes(10)); // t=70m > 65m
        AccessDecision natural = s.h.accessControlService().decide(stillSurfaceValidAccess, "profile:read");
        assertEquals(AccessDeniedReason.TOKEN_EXPIRED, natural.deniedReason());
        log.info("[绝对过期-区分] t=70m 同一访问凭证自然到期 -> reason=TOKEN_EXPIRED，与 SESSION_EXPIRED 可区分");
    }

    @Test
    @DisplayName("到期边界：到期前一刻放行为 ACTIVE，到达到期点立即拒绝并收敛为 EXPIRED")
    void absoluteExpiryBoundaryIsSharpAndStable() {
        TestFixtures.Harness h = newHarness();
        AuthResult login = login(h, "alice", "password123");
        String id = sid(h, login);

        // 期间保持活跃：t=20m、t=40m 各刷新一次（间隔均小于闲置窗口 30m）
        h.clock().advance(Duration.ofMinutes(20));
        AuthResult r20 = h.authService().refresh(login.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, r20.outcome());
        h.clock().advance(Duration.ofMinutes(20));
        AuthResult r40 = h.authService().refresh(r20.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, r40.outcome());

        // 到期前 1 秒：会话存活，串行刷新成功并签发一张新的访问凭证
        h.clock().advance(Duration.ofMinutes(20).minusSeconds(1)); // t=59m59s
        AuthResult justBefore = h.authService().refresh(r40.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, justBefore.outcome());
        String freshAccess = justBefore.tokens().accessToken();
        assertTrue(h.accessControlService().decide(freshAccess, "profile:read").allowed());
        GovernanceResult listBefore = h.governanceService().listSessions("alice", id);
        assertEquals(1, listBefore.sessions().size());
        log.info("[绝对过期-边界] t=59m59s 访问放行/刷新成功/名单存活，状态=ACTIVE");

        // 恰好到达到期点（now == refreshTokenExpiresAt，!isBefore 即到期）：三入口一致拒绝/消失。
        // 终态是入口判定时懒收敛的，故先经访问入口触发收敛，再断言链状态。
        h.clock().advanceSeconds(1);
        AccessDecision accessAt = h.accessControlService().decide(freshAccess, "profile:read");
        assertEquals(AccessDeniedReason.SESSION_EXPIRED, accessAt.deniedReason());
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED,
                h.authService().refresh(justBefore.tokens().refreshToken()).outcome());
        GovernanceResult listAt = h.governanceService().listSessions("alice", id);
        assertEquals(0, listAt.sessions().size());
        assertEquals(SessionState.EXPIRED,
                h.sessionRepository().findById(id).orElseThrow().getState());
        log.info("[绝对过期-边界] t=60m00s 访问=SESSION_EXPIRED/刷新=REFRESH_TOKEN_EXPIRED/名单为空，状态=EXPIRED");
    }

    @Test
    @DisplayName("绝对到期与闲置窗口同时满足时，原因唯一归为绝对过期 EXPIRED")
    void absoluteExpiryTakesPrecedenceOverIdleTimeout() {
        TestFixtures.Harness h = newHarness();
        AuthResult login = login(h, "alice", "password123");
        String id = sid(h, login);

        // t=60m：数学上既到绝对有效期 60m，也满足"无活动超过闲置窗口 30m"。
        // 生命周期原语在两个条件同时成立时必须唯一收敛为 EXPIRED（绝对优先于闲置）。
        h.clock().advance(Duration.ofHours(1));
        SessionState state = h.sessionRepository()
                .evaluateLifecycle(h.sessionRepository().findById(id).orElseThrow(),
                        h.clock().now(), IDLE_TIMEOUT);
        assertEquals(SessionState.EXPIRED, state);
        // 刷新不依赖访问凭证，刷新入口在两条件同时成立时原因必须归为绝对过期
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED,
                h.authService().refresh(login.tokens().refreshToken()).outcome());
        // 注：此处首登访问凭证（15m）已先自然到期，访问入口按短路顺序给 TOKEN_EXPIRED；
        // "表面未到期的访问凭证"在现实流程中必然意味着近期有活动（闲置窗口未到），
        // 那种情况下访问入口给 SESSION_EXPIRED，由 accessAndRefreshAreDeniedWithDistinctReasons 覆盖。
        assertEquals(AccessDeniedReason.TOKEN_EXPIRED,
                h.accessControlService().decide(login.tokens().accessToken(), "profile:read").deniedReason());
        log.info("[绝对过期-优先级] 绝对到期与闲置同时成立 -> 链状态=EXPIRED，刷新 REFRESH_TOKEN_EXPIRED");
    }

    @Test
    @DisplayName("EXPIRED 终态不可被任何后续请求复活（刷新/再访问/再等待/幂等撤销均不改变终态）")
    void expiredTerminalStateCanNeverBeReactivated() {
        ExpiredSetup s = setupAtAbsoluteExpiry();

        // 已进入 EXPIRED：访问、刷新一律拒绝
        assertEquals(AccessDeniedReason.SESSION_EXPIRED, s.h.accessControlService()
                .decide(s.lastRefresh.tokens().accessToken(), "profile:read").deniedReason());
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED,
                s.h.authService().refresh(s.lastRefresh.tokens().refreshToken()).outcome());

        // 再等待更久，终态依旧，不会被任何请求"刷新活"
        s.h.clock().advance(Duration.ofMinutes(30));
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED,
                s.h.authService().refresh(s.lastRefresh.tokens().refreshToken()).outcome());

        // 幂等撤销不得覆盖首个终态：状态仍是 EXPIRED（先到的终态唯一保留）
        GovernanceResult revoke = s.h.governanceService()
                .revokeSession("alice", s.viewerSessionId(), s.expiredSessionId());
        assertEquals(GovernanceOutcome.SESSION_REVOKED, revoke.outcome());
        assertEquals(SessionState.EXPIRED,
                s.h.sessionRepository().findById(s.expiredSessionId).orElseThrow().getState());

        // "撤销其它存活会话"也不会把 EXPIRED 重新计入或改写成 REVOKED
        GovernanceResult revokeOthers = s.h.governanceService()
                .revokeOtherSessions("alice", s.viewerSessionId());
        assertEquals(0, revokeOthers.revokedCount());
        assertEquals(SessionState.EXPIRED,
                s.h.sessionRepository().findById(s.expiredSessionId).orElseThrow().getState());

        // 终态之后再访问/再刷新，结果仍然是拒绝且原因稳定
        AccessDecision after = s.h.accessControlService()
                .decide(s.lastRefresh.tokens().accessToken(), "profile:read");
        assertEquals(AccessDeniedReason.TOKEN_EXPIRED, after.deniedReason(),
                "访问凭证此刻已自然到期，原因稳定为 TOKEN_EXPIRED；会话终态仍为 EXPIRED");
        assertEquals(SessionState.EXPIRED,
                s.h.sessionRepository().findById(s.expiredSessionId).orElseThrow().getState());
        log.info("[绝对过期-终态] EXPIRED 会话历经刷新/等待/撤销后仍为 EXPIRED，绝不复活");
    }

    @Test
    @DisplayName("到期点并发（名单+访问+刷新）：结果唯一收敛，绝无放行/拒绝并存或存活可见性矛盾")
    void concurrentMixedRequestsAtExpiryConvergeUniquely() throws Exception {
        ExpiredSetup s = setupAtAbsoluteExpiry(); // 时钟已停在精确到期点 t=60m
        String expiredAccess = s.lastRefresh.tokens().accessToken();
        String expiredRefresh = s.lastRefresh.tokens().refreshToken();

        int threadsPerKind = 12;
        int total = threadsPerKind * 3;
        ExecutorService pool = Executors.newFixedThreadPool(total);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(total);
        ConcurrentLinkedQueue<String> results = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < threadsPerKind; i++) {
            // 名单：从仍有效的观察会话视角
            pool.submit(() -> runBarrier(start, done, results, "list", () -> {
                GovernanceResult r = s.h.governanceService().listSessions("alice", s.viewerSessionId());
                boolean hidden = r.sessions().stream()
                        .noneMatch(v -> v.sessionId().equals(s.expiredSessionId()));
                return hidden ? "list:hidden" : "list:VISIBLE-BUG";
            }));
            // 访问：用过期会话那张表面未到期的访问凭证
            pool.submit(() -> runBarrier(start, done, results, "access", () -> {
                AccessDecision d = s.h.accessControlService().decide(expiredAccess, "profile:read");
                return d.allowed() ? "access:ALLOWED-BUG" : "access:" + d.deniedReason();
            }));
            // 刷新
            pool.submit(() -> runBarrier(start, done, results, "refresh", () -> {
                AuthResult r = s.h.authService().refresh(expiredRefresh);
                return "refresh:" + r.outcome();
            }));
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        log.info("[绝对过期-并发] t=60m 混合并发 {} 个请求结果={}", total, results);
        assertEquals(total, results.size());
        assertFalse(results.contains("list:VISIBLE-BUG"), "并发下名单绝不能显示已绝对过期会话");
        assertFalse(results.contains("access:ALLOWED-BUG"), "并发下绝不能放行已绝对过期会话的访问");
        assertEquals(threadsPerKind, results.stream().filter("list:hidden"::equals).count());
        assertEquals(threadsPerKind, results.stream().filter("access:SESSION_EXPIRED"::equals).count());
        assertEquals(threadsPerKind, results.stream().filter("refresh:REFRESH_TOKEN_EXPIRED"::equals).count());

        // 最终状态唯一收敛为 EXPIRED；不存在任何"有效的会话链"
        var chain = s.h.sessionRepository().findById(s.expiredSessionId).orElseThrow();
        assertEquals(SessionState.EXPIRED, chain.getState());
        // 链上当前 refresh 凭证继续使用仍被拒，不会重新产生有效链
        AuthResult later = s.h.authService().refresh(chain.getCurrentRefreshToken());
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, later.outcome());
        log.info("[绝对过期-并发] 最终状态唯一=EXPIRED，三类入口结果各自一致，无双链/无复活");
    }

    @Test
    @DisplayName("到期前一刻并发请求全部放行且名单存活，到期点并发全部拒绝：前后两侧均不劈裂")
    void concurrentRequestsAreUniformOnBothSidesOfBoundary() throws Exception {
        TestFixtures.Harness h = newHarness();
        AuthResult login = login(h, "alice", "password123");
        String id = sid(h, login);

        // 期间保持活跃：t=20m、t=40m 各刷新一次（间隔均小于闲置窗口 30m）
        h.clock().advance(Duration.ofMinutes(20));
        AuthResult r20 = h.authService().refresh(login.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, r20.outcome());
        h.clock().advance(Duration.ofMinutes(20));
        AuthResult r40 = h.authService().refresh(r20.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, r40.outcome());

        // ---- 到期前 1 秒（t=59m59s）：并发访问/名单全部放行/可见 ----
        h.clock().advance(Duration.ofMinutes(20).minusSeconds(1));
        AuthResult justBefore = h.authService().refresh(r40.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, justBefore.outcome());
        String freshAccess = justBefore.tokens().accessToken();
        // 到期前只并发"访问 + 名单"：同一 refresh 凭证并发刷新本身按复用设计，会令链撤销，
        // 不属于本用例要验证的时间边界，故不在到期前混入并发刷新。
        ConcurrentMixed before = runConcurrent(h, id, freshAccess,
                justBefore.tokens().refreshToken(), false);
        assertEquals(before.accessTotal, before.accessAllowed, "到期前一刻并发访问必须全部放行");
        assertEquals(before.listTotal, before.listVisible, "到期前一刻并发名单必须全部显示存活");
        assertEquals(SessionState.ACTIVE, h.sessionRepository().findById(id).orElseThrow().getState());
        log.info("[绝对过期-边界并发] t=59m59s 访问放行 {}/{}、名单存活 {}/{}",
                before.accessAllowed, before.accessTotal, before.listVisible, before.listTotal);

        // ---- 推到到期点：并发访问/名单/刷新全部拒绝/消失，无任何放行夹杂 ----
        h.clock().advanceSeconds(1);
        // 到期点三类并发：此时所有刷新都先撞 EXPIRED，根本走不到轮换/复用判定，故结果必然一致
        ConcurrentMixed at = runConcurrent(h, id, freshAccess,
                justBefore.tokens().refreshToken(), true);
        assertEquals(0, at.accessAllowed, "到期点并发访问必须全部拒绝");
        assertEquals(at.accessTotal, resultsCount(at, "access:SESSION_EXPIRED"));
        assertEquals(0, at.listVisible, "到期点并发名单必须全部不显示该会话");
        assertEquals(at.refreshTotal, resultsCount(at, "refresh:REFRESH_TOKEN_EXPIRED"));
        assertEquals(SessionState.EXPIRED, h.sessionRepository().findById(id).orElseThrow().getState());
        log.info("[绝对过期-边界并发] t=60m00s 访问拒绝 {}/{}、名单隐藏 {}/{}、刷新拒绝 {}/{}",
                at.accessTotal, at.accessTotal, at.listTotal - at.listVisible, at.listTotal,
                at.refreshTotal, at.refreshTotal);
    }

    private record ConcurrentMixed(int accessTotal, int accessAllowed,
                                   int listTotal, int listVisible,
                                   int refreshTotal, List<String> raw) {
    }

    private ConcurrentMixed runConcurrent(TestFixtures.Harness h, String sessionId,
                                          String accessToken, String refreshToken,
                                          boolean includeRefresh) throws Exception {
        int perKind = 10;
        int total = perKind * (includeRefresh ? 3 : 2);
        ExecutorService pool = Executors.newFixedThreadPool(total);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(total);
        ConcurrentLinkedQueue<String> results = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < perKind; i++) {
            pool.submit(() -> runBarrier(start, done, results, "access", () -> {
                AccessDecision d = h.accessControlService().decide(accessToken, "profile:read");
                return d.allowed() ? "access:ALLOWED" : "access:" + d.deniedReason();
            }));
            pool.submit(() -> runBarrier(start, done, results, "list", () -> {
                GovernanceResult r = h.governanceService().listSessions("alice", sessionId);
                boolean visible = r.sessions().stream().anyMatch(v -> v.sessionId().equals(sessionId));
                return visible ? "list:visible" : "list:hidden";
            }));
            if (includeRefresh) {
                pool.submit(() -> runBarrier(start, done, results, "refresh", () -> {
                    AuthResult r = h.authService().refresh(refreshToken);
                    return "refresh:" + r.outcome();
                }));
            }
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        List<String> raw = List.copyOf(results);
        int accessTotal = (int) raw.stream().filter(x -> x.startsWith("access:")).count();
        int accessAllowed = (int) raw.stream().filter("access:ALLOWED"::equals).count();
        int listTotal = (int) raw.stream().filter(x -> x.startsWith("list:")).count();
        int listVisible = (int) raw.stream().filter("list:visible"::equals).count();
        int refreshTotal = (int) raw.stream().filter(x -> x.startsWith("refresh:")).count();
        return new ConcurrentMixed(accessTotal, accessAllowed, listTotal, listVisible, refreshTotal, raw);
    }

    private static long resultsCount(ConcurrentMixed m, String value) {
        return m.raw().stream().filter(value::equals).count();
    }

    private void runBarrier(CountDownLatch start, CountDownLatch done,
                            ConcurrentLinkedQueue<String> sink, String ignored,
                            java.util.function.Supplier<String> action) {
        try {
            start.await();
            sink.add(action.get());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            done.countDown();
        }
    }
}
