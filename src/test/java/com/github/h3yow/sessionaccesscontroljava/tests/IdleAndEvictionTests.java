package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.access.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDeniedReason;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import com.github.h3yow.sessionaccesscontroljava.governance.SessionView;
import com.github.h3yow.sessionaccesscontroljava.session.SessionChain;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 闲置治理与容量淘汰：
 * - 闲置超时与凭证绝对过期是两种可区分原因（访问侧 + 刷新侧）；
 * - 闲置是惰性生效：恰在窗口边界仍放行，超过窗口才失效；
 * - 超容量淘汰最久未活动会话，当前/最新会话不被误伤，活跃可"续命"。
 */
class IdleAndEvictionTests {

    private static final Logger log = LoggerFactory.getLogger(IdleAndEvictionTests.class);

    @Test
    void idleTimeoutIsLazyAndDistinctFromAbsoluteExpiry() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String refresh = login.tokens().refreshToken();
        String sessionId = h.sessionRepository().findByRefreshToken(refresh).orElseThrow().getSessionId();

        // 恰在闲置窗口边界：lastActivity(00:00) + 5m == now，边界不算超时，刷新仍成功
        // （刷新成功本身是一次活动，会推进 lastActivity）
        h.clock().advance(TestFixtures.IDLE_TTL);
        AuthResult boundaryRefresh = h.authService().refresh(refresh);
        log.info("CASE idle: 恰在 5m 边界刷新 outcome={}", boundaryRefresh.outcome());
        assertEquals(AuthOutcome.REFRESH_SUCCESS, boundaryRefresh.outcome());
        String rotatedRefresh = boundaryRefresh.tokens().refreshToken();

        // 刷新把活动时间推进到 5m；再推进一个完整闲置窗口 +1s（此刻 10m+1s，
        // 访问凭证 20m 才绝对过期、刷新凭证 12h 才过期），失败原因只能是会话闲置
        h.clock().advance(TestFixtures.IDLE_TTL.plusSeconds(1));
        AccessDecision idleAccess = h.accessControlService()
                .decide(boundaryRefresh.tokens().accessToken(), "profile:read");
        AuthResult idleRefresh = h.authService().refresh(rotatedRefresh);
        log.info("CASE idle: 超过闲置窗口(凭证未绝对过期) access={} refresh={}",
                idleAccess.deniedReason(), idleRefresh.outcome());
        assertEquals(AccessDeniedReason.SESSION_IDLE, idleAccess.deniedReason());
        assertEquals(AuthOutcome.SESSION_IDLE, idleRefresh.outcome());

        // 终态收敛，且从活跃列表消失
        SessionChain chain = h.sessionRepository().findById(sessionId).orElseThrow();
        assertEquals(SessionState.IDLE_TIMEOUT, chain.getState());
        assertTrue(h.governanceService().listSessions("alice", sessionId).sessions().isEmpty());
    }

    @Test
    void absoluteExpiryIsDistinctFromIdleAndFromUnknown() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String refresh = login.tokens().refreshToken();

        // 推进超过刷新凭证绝对有效期（12h），远超闲置窗口
        h.clock().advance(TestFixtures.REFRESH_TTL.plusSeconds(1));
        AuthResult expired = h.authService().refresh(refresh);
        log.info("CASE absolute-expiry: outcome={} (应与 SESSION_IDLE/UNKNOWN 区分)", expired.outcome());
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, expired.outcome());

        // 访问侧：会话已惰性收敛为 EXPIRED -> SESSION_EXPIRED
        AccessDecision accessExpired = h.accessControlService()
                .decide(login.tokens().accessToken(), "profile:read");
        // 访问凭证自身 TTL 也已过 -> 先命中 TOKEN_EXPIRED；改用刷新侧终态断言访问侧会话终态
        SessionChain chain = h.sessionRepository().findByRefreshToken(refresh).orElseThrow();
        assertEquals(SessionState.EXPIRED, chain.getState());
        log.info("CASE absolute-expiry: accessToken 自身 {}，会话终态={}",
                accessExpired.deniedReason(), chain.getState());
        assertEquals(AccessDeniedReason.TOKEN_EXPIRED, accessExpired.deniedReason());

        // 不可识别凭证仍是独立原因
        AuthResult unknown = h.authService().refresh("garbage-token");
        assertEquals(AuthOutcome.REFRESH_TOKEN_UNKNOWN, unknown.outcome());
    }

    @Test
    void activityResetsIdleClock() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult current = h.authService().login("alice", "password123");
        // 每次活动后推进 1 分钟（< 闲置窗口 5m），连续多次仍存活
        for (int i = 0; i < 5; i++) {
            h.clock().advance(Duration.ofMinutes(1));
            current = h.authService().refresh(current.tokens().refreshToken());
            assertEquals(AuthOutcome.REFRESH_SUCCESS, current.outcome(),
                    "第 " + i + " 次 1m 间隔刷新应成功（活动续命）");
        }
        log.info("CASE idle-reset: 多次 1m 间隔活动后会话仍可刷新");

        // 停止活动超过窗口 -> 失效
        h.clock().advance(TestFixtures.IDLE_TTL.plusSeconds(1));
        assertEquals(AuthOutcome.SESSION_IDLE,
                h.authService().refresh(current.tokens().refreshToken()).outcome());
    }

    @Test
    void overCapacityEvictsOldestIdleSessionAndNeverTheNewest() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        // cap=3：登录 3 端
        AuthResult s1 = h.authService().login("alice", "password123");
        h.clock().advanceSeconds(10);
        AuthResult s2 = h.authService().login("alice", "password123");
        h.clock().advanceSeconds(10);
        AuthResult s3 = h.authService().login("alice", "password123");
        h.clock().advanceSeconds(10);
        // 第 4 端登录 -> 最久未活动的 s1 被淘汰
        AuthResult s4 = h.authService().login("alice", "password123");

        Map<String, SessionChain> chains = h.sessionRepository().chainsOf("alice").stream()
                .collect(Collectors.toMap(SessionChain::getSessionId, Function.identity()));
        SessionChain c1 = h.sessionRepository().findByRefreshToken(s1.tokens().refreshToken()).orElseThrow();
        SessionChain c4 = h.sessionRepository().findByRefreshToken(s4.tokens().refreshToken()).orElseThrow();
        log.info("CASE eviction: s1 state={} s4 state={} total={}", c1.getState(), c4.getState(), chains.size());
        assertEquals(SessionState.EVICTED, c1.getState());
        assertEquals(SessionState.ACTIVE, c4.getState());
        assertEquals(SessionState.ACTIVE,
                h.sessionRepository().findByRefreshToken(s2.tokens().refreshToken()).orElseThrow().getState());
        assertEquals(SessionState.ACTIVE,
                h.sessionRepository().findByRefreshToken(s3.tokens().refreshToken()).orElseThrow().getState());

        // 被淘汰端：访问 SESSION_EVICTED，刷新 SESSION_EVICTED（与撤销/过期区分）
        AccessDecision evictedAccess = h.accessControlService()
                .decide(s1.tokens().accessToken(), "profile:read");
        AuthResult evictedRefresh = h.authService().refresh(s1.tokens().refreshToken());
        log.info("CASE eviction: access reason={}, refresh outcome={}",
                evictedAccess.deniedReason(), evictedRefresh.outcome());
        assertEquals(AccessDeniedReason.SESSION_EVICTED, evictedAccess.deniedReason());
        assertEquals(AuthOutcome.SESSION_EVICTED, evictedRefresh.outcome());

        // 最新端不受影响，列表恰好 3 条活跃
        assertTrue(h.accessControlService().decide(s4.tokens().accessToken(), "profile:read").allowed());
        assertEquals(3, h.governanceService().listSessions("alice", c4.getSessionId()).sessions().size());
    }

    @Test
    void recentActivityProtectsSessionFromEviction() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult s1 = h.authService().login("alice", "password123");
        h.clock().advanceSeconds(10);
        AuthResult s2 = h.authService().login("alice", "password123");
        h.clock().advanceSeconds(10);
        AuthResult s3 = h.authService().login("alice", "password123");

        // s1 虽登录最早，但刚刚发生过访问 -> 最近活动时间最新，不应被淘汰
        h.clock().advanceSeconds(10);
        assertTrue(h.accessControlService().decide(s1.tokens().accessToken(), "profile:read").allowed());
        h.clock().advanceSeconds(10);
        AuthResult s4 = h.authService().login("alice", "password123");

        SessionChain c1 = h.sessionRepository().findByRefreshToken(s1.tokens().refreshToken()).orElseThrow();
        SessionChain c2 = h.sessionRepository().findByRefreshToken(s2.tokens().refreshToken()).orElseThrow();
        log.info("CASE eviction-activity: s1(刚活动) state={}, s2 state={}", c1.getState(), c2.getState());
        assertEquals(SessionState.ACTIVE, c1.getState());
        assertEquals(SessionState.EVICTED, c2.getState());
    }

    @Test
    void otherUsersSessionsDoNotShareCapacity() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult a1 = h.authService().login("alice", "password123");
        h.clock().advanceSeconds(1);
        h.authService().login("alice", "password123");
        h.clock().advanceSeconds(1);
        h.authService().login("alice", "password123");
        h.clock().advanceSeconds(1);
        h.authService().login("alice", "password123"); // 淘汰 alice 的一条

        // bob 的容量独立计算，其第一条绝不被 alice 的淘汰波及
        AuthResult b1 = h.authService().login("bob", "bob123");
        assertTrue(h.accessControlService().decide(b1.tokens().accessToken(), "profile:read").allowed());
        assertEquals(SessionState.ACTIVE,
                h.sessionRepository().findByRefreshToken(b1.tokens().refreshToken()).orElseThrow().getState());

        // alice 在第 4 次登录后恰好保持 cap=3 条活跃，且全是 alice 自己的
        var aliceSessions = h.governanceService().listSessions("alice",
                h.sessionRepository().findByRefreshToken(a1.tokens().refreshToken())
                        .map(c -> c.getSessionId()).orElse("none")).sessions();
        assertEquals(3, aliceSessions.size());
        var bobSessions = h.governanceService().listSessions("bob",
                h.sessionRepository().findByRefreshToken(b1.tokens().refreshToken())
                        .orElseThrow().getSessionId()).sessions();
        assertEquals(1, bobSessions.size());
    }
}
