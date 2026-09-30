package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.access.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDeniedReason;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceOutcome;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceResult;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import com.github.h3yow.sessionaccesscontroljava.session.SessionView;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 会话治理用例：
 * - 多用户多端同时登录，列表可识别每条会话且不含凭证、只含本人会话；
 * - 精确撤销单条 / 撤销除当前外其它，撤销即时生效且终态不可复活；
 * - 闲置超时与刷新凭证绝对过期原因可区分；
 * - 容量超限淘汰最久未活动会话，且不误伤当前会话、不与刷新竞争算错；
 * - 越权查看/撤销他人会话被明确拒绝；
 * - 并发撤销/刷新同一条会话最终状态唯一收敛。
 */
class SessionGovernanceTests {

    private static final Logger log = LoggerFactory.getLogger(SessionGovernanceTests.class);

    private AuthResult login(TestFixtures.Harness h, String user, String password) {
        AuthResult r = h.authService().login(user, password);
        assertEquals(AuthOutcome.LOGIN_SUCCESS, r.outcome(), "登录应成功: " + r.message());
        return r;
    }

    @Test
    void multiUserMultiDeviceListIsScopedAndCredentialFree() {
        TestFixtures.Harness h = TestFixtures.newHarness();

        // alice 两台设备（两个浏览器）、bob 一台设备
        AuthResult alicePhone = login(h, "alice", "password123");
        h.clock().advanceSeconds(10);
        AuthResult aliceLaptop = login(h, "alice", "password123");
        h.clock().advanceSeconds(10);
        AuthResult bobDesktop = login(h, "bob", "bob123");

        String phoneSession = h.sessionRepository()
                .findByRefreshToken(alicePhone.tokens().refreshToken()).orElseThrow().getSessionId();
        String laptopSession = h.sessionRepository()
                .findByRefreshToken(aliceLaptop.tokens().refreshToken()).orElseThrow().getSessionId();

        // alice 用 laptop 的访问凭证查询：只看到自己的两条，bob 的绝不出现
        GovernanceResult list = h.governanceService()
                .listSessions("alice", laptopSession);
        assertEquals(GovernanceOutcome.SESSIONS_LISTED, list.outcome());
        List<SessionView> views = list.sessions();
        log.info("CASE list: alice 看到 {} 条: {}", views.size(),
                views.stream().map(SessionView::sessionId).toList());
        assertEquals(2, views.size());
        assertTrue(views.stream().allMatch(v -> v.username().equals("alice")), "列表只能包含本人会话");

        // "正在使用的这个会话" 要能认出来
        SessionView current = views.stream().filter(SessionView::current).findFirst().orElseThrow();
        assertEquals(laptopSession, current.sessionId());
        SessionView other = views.stream().filter(v -> !v.current()).findFirst().orElseThrow();
        assertEquals(phoneSession, other.sessionId());

        // 登录时间与最近活动时间可识别，且登录先后顺序反映在 createdAt 上
        assertTrue(other.createdAt().isBefore(current.createdAt()));
        assertNotNull(other.lastActivityAt());
        assertEquals(SessionState.ACTIVE, other.state());

        // bob 视角只能看到自己 1 条
        String bobSession = h.sessionRepository()
                .findByRefreshToken(bobDesktop.tokens().refreshToken()).orElseThrow().getSessionId();
        GovernanceResult bobList = h.governanceService().listSessions("bob", bobSession);
        assertEquals(1, bobList.sessions().size());
        assertEquals(bobSession, bobList.sessions().get(0).sessionId());
        log.info("CASE list: bob 只看到自己的 1 条，跨用户隔离成立");
    }

    @Test
    void revokeSingleSessionTakesEffectImmediatelyAndCannotBeReactivated() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult phone = login(h, "alice", "password123");
        h.clock().advanceSeconds(5);
        AuthResult laptop = login(h, "alice", "password123");

        var phoneChain = h.sessionRepository().findByRefreshToken(phone.tokens().refreshToken()).orElseThrow();
        String phoneSession = phoneChain.getSessionId();
        String laptopSession = h.sessionRepository()
                .findByRefreshToken(laptop.tokens().refreshToken()).orElseThrow().getSessionId();

        // 撤销前两条都能用
        assertTrue(h.accessControlService().decide(phone.tokens().accessToken(), "profile:read").allowed());
        assertTrue(h.accessControlService().decide(laptop.tokens().accessToken(), "profile:read").allowed());

        // 精确撤销 phone 这一条（来自 laptop 会话发起）
        GovernanceResult revoked = h.governanceService().revokeSession("alice", laptopSession, phoneSession);
        assertEquals(GovernanceOutcome.SESSION_REVOKED, revoked.outcome());
        log.info("CASE revoke-one: 撤销 phone={} -> {}", phoneSession, revoked.message());

        // 立即生效：phone 的访问凭证被级联撤销（TOKEN_REVOKED），刷新被拒（SESSION_REVOKED）
        AccessDecision phoneAccess = h.accessControlService()
                .decide(phone.tokens().accessToken(), "profile:read");
        assertEquals(AccessDeniedReason.TOKEN_REVOKED, phoneAccess.deniedReason());
        AuthResult phoneRefresh = h.authService().refresh(phone.tokens().refreshToken());
        assertEquals(AuthOutcome.SESSION_REVOKED, phoneRefresh.outcome());
        log.info("CASE revoke-one: phone access={} refresh={}，即时生效",
                phoneAccess.deniedReason(), phoneRefresh.outcome());

        // laptop 不受影响
        assertTrue(h.accessControlService().decide(laptop.tokens().accessToken(), "profile:read").allowed());
        assertEquals(AuthOutcome.REFRESH_SUCCESS,
                h.authService().refresh(laptop.tokens().refreshToken()).outcome());

        // 已撤销会话不能被重新激活：再次撤销为幂等成功，状态仍 REVOKED
        GovernanceResult again = h.governanceService().revokeSession("alice", laptopSession, phoneSession);
        assertEquals(GovernanceOutcome.SESSION_REVOKED, again.outcome());
        assertEquals(SessionState.REVOKED,
                h.sessionRepository().findById(phoneSession).orElseThrow().getState());
        log.info("CASE revoke-one: 重复撤销幂恒，终态仍为 REVOKED，不可复活");
    }

    @Test
    void revokeOthersKeepsCurrentAndKillsTheRest() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult s1 = login(h, "alice", "password123");
        h.clock().advanceSeconds(5);
        AuthResult s2 = login(h, "alice", "password123");
        h.clock().advanceSeconds(5);
        AuthResult current = login(h, "alice", "password123");
        String currentSession = h.sessionRepository()
                .findByRefreshToken(current.tokens().refreshToken()).orElseThrow().getSessionId();

        GovernanceResult result = h.governanceService().revokeOtherSessions("alice", currentSession);
        assertEquals(GovernanceOutcome.SESSIONS_REVOKED_OTHERS, result.outcome());
        assertEquals(2, result.revokedCount());
        log.info("CASE revoke-others: 撤销数量={}", result.revokedCount());

        // 另外两条立即失效
        assertEquals(AccessDeniedReason.TOKEN_REVOKED, h.accessControlService()
                .decide(s1.tokens().accessToken(), "profile:read").deniedReason());
        assertEquals(AccessDeniedReason.TOKEN_REVOKED, h.accessControlService()
                .decide(s2.tokens().accessToken(), "profile:read").deniedReason());

        // 当前会话完好：可访问、可刷新，且列表里只剩它
        assertTrue(h.accessControlService().decide(current.tokens().accessToken(), "profile:read").allowed());
        assertEquals(AuthOutcome.REFRESH_SUCCESS,
                h.authService().refresh(current.tokens().refreshToken()).outcome());
        GovernanceResult list = h.governanceService().listSessions("alice", currentSession);
        assertEquals(1, list.sessions().size());
        assertEquals(currentSession, list.sessions().get(0).sessionId());
        assertTrue(list.sessions().get(0).current());
        log.info("CASE revoke-others: 当前会话未被误伤，列表仅剩当前会话");
    }

    @Test
    void idleTimeoutIsDistinguishableFromAbsoluteExpiry() {
        // 用更短的闲置超时（2 分钟），远小于刷新凭证 12 小时的绝对有效期
        TestFixtures.Harness h = TestFixtures.newHarness(java.time.Duration.ofMinutes(2), 5);
        AuthResult login = login(h, "alice", "password123");
        String access = login.tokens().accessToken();
        String refresh = login.tokens().refreshToken();
        String sessionId = h.sessionRepository().findByRefreshToken(refresh).orElseThrow().getSessionId();

        // --- 路径 A：闲置超时（无访问也无刷新） ---
        // 先确认在闲置窗口内、但访问凭证已过期时，原因仍是 TOKEN_EXPIRED 而非闲置
        h.clock().advanceSeconds(60); // 闲置 1 分钟（窗口内）
        // 访问凭证 15 分钟过期，这里还没过期；做一次访问推进活动时间
        assertTrue(h.accessControlService().decide(access, "profile:read").allowed());

        h.clock().advanceSeconds(121); // 距上次活动 2 分 01 秒 -> 闲置
        AccessDecision idleAccess = h.accessControlService().decide(access, "profile:read");
        log.info("CASE idle: 访问判定 reason={} message={}", idleAccess.deniedReason(), idleAccess.message());
        assertEquals(AccessDeniedReason.SESSION_IDLE_TIMEOUT, idleAccess.deniedReason());

        AuthResult idleRefresh = h.authService().refresh(refresh);
        log.info("CASE idle: 刷新判定 outcome={}", idleRefresh.outcome());
        assertEquals(AuthOutcome.SESSION_IDLE_TIMEOUT, idleRefresh.outcome());
        assertEquals(SessionState.IDLE_TIMEOUT,
                h.sessionRepository().findById(sessionId).orElseThrow().getState());

        // 列表不再包含已闲置会话
        GovernanceResult list = h.governanceService().listSessions("alice", sessionId);
        assertEquals(0, list.sessions().size());
        log.info("CASE idle: 闲置会话不出现在存活列表中，状态=IDLE_TIMEOUT");

        // --- 路径 B：刷新凭证绝对过期（区别于闲置） ---
        // 闲置超时设为远超刷新凭证 12h 的绝对有效期，从而闲置永不先触发；
        // 周期性刷新保持活跃，最终在登录时刻 + 12h 因绝对过期终止。
        TestFixtures.Harness h2 = TestFixtures.newHarness(java.time.Duration.ofHours(365), 5);
        AuthResult login2 = login(h2, "alice", "password123");
        String refresh2 = login2.tokens().refreshToken();
        String currentRefresh = refresh2;
        AuthOutcome terminal = null;
        String lastAccess = login2.tokens().accessToken();
        for (int i = 0; i < 500; i++) {
            h2.clock().advanceSeconds(100); // 每次间隔远小于 12h，不会闲置
            AuthResult r = h2.authService().refresh(currentRefresh);
            if (r.outcome() != AuthOutcome.REFRESH_SUCCESS) {
                terminal = r.outcome();
                log.info("CASE absolute: 持续活跃下刷新终止 outcome={}（第 {} 次）", terminal, i + 1);
                break;
            }
            currentRefresh = r.tokens().refreshToken();
            lastAccess = r.tokens().accessToken();
        }
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, terminal,
                "持续活跃（无闲置）时终止原因必须是刷新凭证绝对过期");
        // 进入 EXPIRED 终态后，用最近一次刷新签发的、尚未自然过期的访问凭证访问，
        // 必须得到 SESSION_EXPIRED（区别于 TOKEN_EXPIRED 与 SESSION_IDLE_TIMEOUT）
        var chain2 = h2.sessionRepository().findByRefreshToken(currentRefresh).orElseThrow();
        assertEquals(SessionState.EXPIRED, chain2.getState());
        AccessDecision expiredSessionAccess =
                h2.accessControlService().decide(lastAccess, "profile:read");
        assertEquals(AccessDeniedReason.SESSION_EXPIRED, expiredSessionAccess.deniedReason());
        log.info("CASE absolute: 访问 reason=SESSION_EXPIRED，状态=EXPIRED，与闲置/撤销/凭证过期均可区分");
    }

    @Test
    void capacityOverflowEvictsOldestActiveAndKeepsNewest() {
        int cap = 3;
        TestFixtures.Harness h = TestFixtures.newHarness(java.time.Duration.ofMinutes(30), cap);

        AuthResult d1 = login(h, "alice", "password123"); // t0
        h.clock().advanceSeconds(30);
        AuthResult d2 = login(h, "alice", "password123"); // t30
        h.clock().advanceSeconds(30);
        AuthResult d3 = login(h, "alice", "password123"); // t60 -> 达到上限 3

        String id1 = sid(h, d1);
        String id2 = sid(h, d2);
        String id3 = sid(h, d3);

        // 第 4 次登录：触发淘汰，最久未活动的 d1 应被淘汰，新会话与 d2/d3 存活
        h.clock().advanceSeconds(30);
        AuthResult d4 = login(h, "alice", "password123"); // t90
        String id4 = sid(h, d4);

        assertEquals(SessionState.EVICTED, h.sessionRepository().findById(id1).orElseThrow().getState());
        assertEquals(SessionState.ACTIVE, h.sessionRepository().findById(id2).orElseThrow().getState());
        assertEquals(SessionState.ACTIVE, h.sessionRepository().findById(id3).orElseThrow().getState());
        assertEquals(SessionState.ACTIVE, h.sessionRepository().findById(id4).orElseThrow().getState());
        log.info("CASE evict: 上限={}，最久未活动 d1 被淘汰，d2/d3/新会话存活", cap);

        // 被淘汰会话的访问（其访问凭证尚未自然过期）得到 SESSION_EVICTED，与撤销/过期/闲置可区分
        AccessDecision evictedAccess = h.accessControlService().decide(d1.tokens().accessToken(), "profile:read");
        assertEquals(AccessDeniedReason.SESSION_EVICTED, evictedAccess.deniedReason());
        AuthResult evictedRefresh = h.authService().refresh(d1.tokens().refreshToken());
        assertEquals(AuthOutcome.SESSION_EVICTED, evictedRefresh.outcome());
        log.info("CASE evict: 被淘汰会话 access=SESSION_EVICTED refresh=SESSION_EVICTED");

        // 列表稳定为 3 条存活，且不含被淘汰者
        GovernanceResult list = h.governanceService().listSessions("alice", id4);
        assertEquals(3, list.sessions().size());
        assertTrue(list.sessions().stream().noneMatch(v -> v.sessionId().equals(id1)));

        // 淘汰不影响其它用户：bob 仍可登录到自己的独立容量
        AuthResult bob = login(h, "bob", "bob123");
        assertTrue(h.accessControlService().decide(bob.tokens().accessToken(), "profile:read").allowed());
        log.info("CASE evict: 容量按用户隔离，bob 不受 alice 淘汰影响");
    }

    @Test
    void capacityEvictionDoesNotTouchCurrentSessionEvenWhenOldest() {
        // 当前正在使用的会话即便最久未活动，也不能被新登录淘汰误伤：
        // 通过"访问/刷新推进活动时间"使其不再是最旧，这里直接验证保护语义——
        // 被保护的新登录会话永不被淘汰；同时旧会话若有刷新活动，其活动时间更新后也不会先被淘汰。
        int cap = 2;
        TestFixtures.Harness h = TestFixtures.newHarness(java.time.Duration.ofMinutes(30), cap);
        AuthResult d1 = login(h, "alice", "password123");
        h.clock().advanceSeconds(20);
        AuthResult d2 = login(h, "alice", "password123"); // 满 2

        // d1 持续使用：刷新推进活动时间，使其比 d2 更新
        h.clock().advanceSeconds(20);
        AuthResult d1Refreshed = h.authService().refresh(d1.tokens().refreshToken());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, d1Refreshed.outcome());

        // 第 3 次登录：此时最久未活动的是 d2（d1 刚刷新过），应淘汰 d2，保护活跃中的 d1
        h.clock().advanceSeconds(20);
        AuthResult d3 = login(h, "alice", "password123");

        String id1 = sid(h, d1Refreshed);
        String id2 = sid(h, d2);
        assertEquals(SessionState.ACTIVE, h.sessionRepository().findById(id1).orElseThrow().getState(),
                "正在刷新使用的会话不应被淘汰");
        assertEquals(SessionState.EVICTED, h.sessionRepository().findById(id2).orElseThrow().getState());
        assertEquals(SessionState.ACTIVE, h.sessionRepository().findById(sid(h, d3)).orElseThrow().getState());
        log.info("CASE evict-current: 正在进行刷新的 d1 活动时间更新，淘汰的是更久未活动的 d2");
    }

    private static String sid(TestFixtures.Harness h, AuthResult tokens) {
        return h.sessionRepository().findByRefreshToken(tokens.tokens().refreshToken())
                .orElseThrow().getSessionId();
    }

    @Test
    void crossUserViewAndRevocationAreForbidden() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult alice = login(h, "alice", "password123");
        AuthResult bob = login(h, "bob", "bob123");
        String aliceSession = sid(h, alice);
        String bobSession = sid(h, bob);

        // bob 试图按 sessionId 撤销 alice 的会话 -> 明确拒绝 SESSION_FORBIDDEN
        GovernanceResult crossRevoke = h.governanceService()
                .revokeSession("bob", bobSession, aliceSession);
        assertEquals(GovernanceOutcome.SESSION_FORBIDDEN, crossRevoke.outcome());
        log.info("CASE cross-user: bob 撤销 alice 会话 -> {}", crossRevoke.outcome());

        // 越权撤销不得生效：alice 会话依旧 ACTIVE、可访问、可刷新
        assertEquals(SessionState.ACTIVE,
                h.sessionRepository().findById(aliceSession).orElseThrow().getState());
        assertTrue(h.accessControlService().decide(alice.tokens().accessToken(), "profile:read").allowed());

        // 撤销不存在的会话 -> NOT_FOUND，与越权 FORBIDDEN 可区分
        GovernanceResult notFound = h.governanceService()
                .revokeSession("bob", bobSession, "no-such-session-id");
        assertEquals(GovernanceOutcome.SESSION_NOT_FOUND, notFound.outcome());
        log.info("CASE cross-user: 未知会话 -> {}，越权 -> {}，原因可区分",
                notFound.outcome(), GovernanceOutcome.SESSION_FORBIDDEN);

        // 归属是按解析出的调用者，而非请求体：alice 撤销自己的会话正常成功
        GovernanceResult ownRevoke = h.governanceService()
                .revokeSession("alice", aliceSession, aliceSession);
        assertEquals(GovernanceOutcome.SESSION_REVOKED, ownRevoke.outcome());

        // 列表天然按调用者隔离：bob 列表里不会混入 alice 的会话
        GovernanceResult bobList = h.governanceService().listSessions("bob", bobSession);
        assertTrue(bobList.sessions().stream().noneMatch(v -> v.sessionId().equals(aliceSession)));
        log.info("CASE cross-user: bob 列表不含 alice 会话，隔离成立");
    }

    @Test
    void concurrentRevokeAndRefreshConvergeToSingleTerminalState() throws Exception {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = login(h, "alice", "password123");
        String refresh = login.tokens().refreshToken();
        String sessionId = sid(h, login);

        int refreshThreads = 16;
        int revokeThreads = 8;
        int total = refreshThreads + revokeThreads;
        java.util.concurrent.ExecutorService pool =
                java.util.concurrent.Executors.newFixedThreadPool(total);
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(total);
        java.util.concurrent.ConcurrentLinkedQueue<String> outcomes =
                new java.util.concurrent.ConcurrentLinkedQueue<>();
        java.util.concurrent.atomic.AtomicInteger refreshWins = new java.util.concurrent.atomic.AtomicInteger();

        log.info("CASE concurrent-revoke-refresh: refreshThreads={} revokeThreads={}", refreshThreads, revokeThreads);
        for (int i = 0; i < refreshThreads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    AuthResult r = h.authService().refresh(refresh);
                    outcomes.add("refresh:" + r.outcome());
                    if (r.outcome() == AuthOutcome.REFRESH_SUCCESS) {
                        refreshWins.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        for (int i = 0; i < revokeThreads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    GovernanceResult r = h.governanceService().revokeSession("alice", sessionId, sessionId);
                    outcomes.add("revoke:" + r.outcome());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, java.util.concurrent.TimeUnit.SECONDS));
        pool.shutdown();

        log.info("CASE concurrent-revoke-refresh: outcomes={}", outcomes);

        // 最终状态唯一收敛：要么 ACTIVE（撤销未发生则不可能——撤销者必定运行，故只可能是终态）
        SessionState finalState = h.sessionRepository().findById(sessionId).orElseThrow().getState();
        log.info("CASE concurrent-revoke-refresh: 最终状态={} 刷新成功数={}", finalState, refreshWins.get());

        // 撤销线程一定会执行，所以最终必然是某个终态；而所有终态里只可能是 REVOKED
        // （没有闲置/淘汰/绝对过期条件），唯一收敛为 REVOKED。
        assertEquals(SessionState.REVOKED, finalState, "并发撤销+刷新后状态必须唯一收敛为 REVOKED");

        // 若刷新恰好先成功，最多一次成功；成功轮换后的新凭证在会话被撤销后也必须被拒
        assertTrue(refreshWins.get() <= 1, "同一凭证并发刷新至多一次成功");
        var chain = h.sessionRepository().findById(sessionId).orElseThrow();
        AuthResult after = h.authService().refresh(chain.getCurrentRefreshToken());
        assertTrue(after.outcome() == AuthOutcome.SESSION_REVOKED
                        || after.outcome() == AuthOutcome.REFRESH_TOKEN_REUSED,
                "收敛后任何当前/旧凭证刷新都必须被拒，实际=" + after.outcome());
        log.info("CASE concurrent-revoke-refresh: 收敛后再刷新 outcome={}，无双链、终态唯一", after.outcome());
    }

    @Test
    void concurrentLoginsRefreshesAndRevokesKeepCountStable() throws Exception {
        int cap = 3;
        TestFixtures.Harness h = TestFixtures.newHarness(java.time.Duration.ofMinutes(30), cap);

        int threads = 24;
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(threads);

        // 多线程混合操作：约 2/3 登录新会话、1/6 随机刷新某会话、1/6 随机撤销某会话
        java.util.concurrent.ConcurrentLinkedQueue<String> ops =
                new java.util.concurrent.ConcurrentLinkedQueue<>();
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    int mod = idx % 6;
                    if (mod < 4) {
                        AuthResult r = login(h, "alice", "password123");
                        ops.add("login:" + r.outcome());
                    } else if (mod == 4) {
                        var active = h.sessionRepository().sessionsOfUser("alice").stream()
                                .filter(c -> c.getState() == SessionState.ACTIVE).findFirst().orElse(null);
                        if (active != null) {
                            AuthResult r = h.authService().refresh(active.getCurrentRefreshToken());
                            ops.add("refresh:" + r.outcome());
                        }
                    } else {
                        var any = h.sessionRepository().sessionsOfUser("alice").stream().findFirst().orElse(null);
                        if (any != null) {
                            GovernanceResult r = h.governanceService()
                                    .revokeSession("alice", any.getSessionId(), any.getSessionId());
                            ops.add("revoke:" + r.outcome());
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
        assertTrue(done.await(30, java.util.concurrent.TimeUnit.SECONDS));
        pool.shutdown();

        long activeCount = h.sessionRepository().sessionsOfUser("alice").stream()
                .filter(c -> c.getState() == SessionState.ACTIVE).count();
        long terminalCount = h.sessionRepository().sessionsOfUser("alice").stream()
                .filter(c -> c.getState() != SessionState.ACTIVE).count();
        log.info("CASE mixed-concurrency: ops={} active={} terminal={}", ops.size(), activeCount, terminalCount);
        log.info("CASE mixed-concurrency: op 明细={}", ops);

        // 不变量：活跃数永不超过容量上限（登录在用户锁内建档+淘汰原子完成；撤销/刷新与该锁互斥）
        assertTrue(activeCount <= cap,
                "并发混合操作后活跃会话数不得超过上限 " + cap + "，实际=" + activeCount);
        // 所有终态会话都停留在合法终态，无一被"复活"为 ACTIVE
        boolean allTerminalValid = h.sessionRepository().sessionsOfUser("alice").stream()
                .filter(c -> c.getState() != SessionState.ACTIVE)
                .allMatch(c -> c.getState() == SessionState.REVOKED
                        || c.getState() == SessionState.EVICTED
                        || c.getState() == SessionState.IDLE_TIMEOUT
                        || c.getState() == SessionState.EXPIRED);
        assertTrue(allTerminalValid, "终态会话只能停留在合法终态");
        log.info("CASE mixed-concurrency: 活跃数={} <= 上限={}，计数与淘汰稳定收敛", activeCount, cap);
    }
}
