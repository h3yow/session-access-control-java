package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.access.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDeniedReason;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceOutcome;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceResult;
import com.github.h3yow.sessionaccesscontroljava.governance.SessionView;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 会话治理：多用户多端登录的列表隔离、单条撤销、撤销其他、越权拒绝、终态不可重新激活，
 * 以及撤销后访问/刷新立即失败且原因可区分。
 */
class SessionGovernanceTests {

    private static final Logger log = LoggerFactory.getLogger(SessionGovernanceTests.class);

    /** 用用户名+序号登录，返回该端当前的凭证对。 */
    private AuthResult login(TestFixtures.Harness h, String username, String password) {
        return h.authService().login(username, password);
    }

    @Test
    void multiUserMultiDeviceSessionsAreListedWithMetadataAndNoTokens() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult alice1 = login(h, "alice", "password123");
        h.clock().advanceSeconds(10);
        AuthResult alice2 = login(h, "alice", "password123");
        h.clock().advanceSeconds(10);
        AuthResult bob1 = login(h, "bob", "bob123");

        // 以 alice 的第二端为"当前会话"
        String alice2SessionId = h.sessionRepository()
                .findByRefreshToken(alice2.tokens().refreshToken()).orElseThrow().getSessionId();
        GovernanceResult aliceList = h.governanceService().listSessions("alice", alice2SessionId);
        GovernanceResult bobList = h.governanceService().listSessions("bob",
                h.sessionRepository().findByRefreshToken(bob1.tokens().refreshToken())
                        .orElseThrow().getSessionId());

        log.info("CASE list: alice sessions={}, bob sessions={}",
                aliceList.sessions().size(), bobList.sessions().size());
        assertEquals(GovernanceOutcome.LIST_SUCCESS, aliceList.outcome());
        assertEquals(2, aliceList.sessions().size());
        assertEquals(1, bobList.sessions().size());

        // 越权隔离：alice 的列表里绝不能出现 bob 的会话
        for (SessionView v : aliceList.sessions()) {
            assertNotEquals(bobList.sessions().get(0).sessionId(), v.sessionId());
        }

        // 当前会话标记正确
        SessionView current = aliceList.sessions().stream()
                .filter(SessionView::current).findFirst().orElseThrow();
        assertEquals(alice2SessionId, current.sessionId());
        assertFalse(aliceList.sessions().get(0).sessionId().isBlank());

        // 元数据：登录时间/最近活动时间存在，且最近活动倒序；视图不含任何凭证字段（record 组件层面保证）
        assertNotNull(current.createdAt());
        assertNotNull(current.lastActivityAt());
        assertNotNull(current.refreshExpiresAt());
        assertTrue(aliceList.sessions().get(0).lastActivityAt()
                .isAfter(aliceList.sessions().get(1).lastActivityAt())
                || aliceList.sessions().get(0).lastActivityAt()
                .equals(aliceList.sessions().get(1).lastActivityAt()));
        assertEquals(5, SessionView.class.getRecordComponents().length);
    }

    @Test
    void revokeOneSessionKillsItImmediatelyAndLeavesCurrentAlive() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult a = login(h, "alice", "password123");
        h.clock().advanceSeconds(5);
        AuthResult b = login(h, "alice", "password123");
        String sessionA = h.sessionRepository().findByRefreshToken(a.tokens().refreshToken())
                .orElseThrow().getSessionId();
        String sessionB = h.sessionRepository().findByRefreshToken(b.tokens().refreshToken())
                .orElseThrow().getSessionId();

        GovernanceResult revoked = h.governanceService().revokeSession("alice", sessionB, sessionA);
        log.info("CASE revoke-one: outcome={} affected={}", revoked.outcome(), revoked.affected());
        assertEquals(GovernanceOutcome.REVOKE_SESSION_SUCCESS, revoked.outcome());
        assertEquals(1, revoked.affected());

        // 被撤销端：访问与刷新立即失败，且原因分别为 TOKEN_REVOKED / SESSION_REVOKED
        AccessDecision accessDenied = h.accessControlService().decide(a.tokens().accessToken(), "profile:read");
        AuthResult refreshDenied = h.authService().refresh(a.tokens().refreshToken());
        log.info("CASE revoke-one: access reason={}, refresh outcome={}",
                accessDenied.deniedReason(), refreshDenied.outcome());
        assertFalse(accessDenied.allowed());
        assertEquals(AccessDeniedReason.TOKEN_REVOKED, accessDenied.deniedReason());
        assertEquals(AuthOutcome.SESSION_REVOKED, refreshDenied.outcome());

        // 当前端仍可用
        AccessDecision currentAccess = h.accessControlService().decide(b.tokens().accessToken(), "profile:read");
        assertTrue(currentAccess.allowed());
        assertEquals(sessionB, currentAccess.sessionId());

        // 列表中只剩当前端
        List<SessionView> remaining = h.governanceService().listSessions("alice", sessionB).sessions();
        assertEquals(1, remaining.size());
        assertEquals(sessionB, remaining.get(0).sessionId());
    }

    @Test
    void revokeAlreadyTerminalSessionIsRejectedAndCannotBeReactivated() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult a = login(h, "alice", "password123");
        AuthResult b = login(h, "alice", "password123");
        String sessionA = h.sessionRepository().findByRefreshToken(a.tokens().refreshToken())
                .orElseThrow().getSessionId();
        String sessionB = h.sessionRepository().findByRefreshToken(b.tokens().refreshToken())
                .orElseThrow().getSessionId();

        assertEquals(GovernanceOutcome.REVOKE_SESSION_SUCCESS,
                h.governanceService().revokeSession("alice", sessionB, sessionA).outcome());

        // 再次撤销同一条：明确告知已不活跃，而不是成功或静默
        GovernanceResult second = h.governanceService().revokeSession("alice", sessionB, sessionA);
        log.info("CASE re-revoke: outcome={}", second.outcome());
        assertEquals(GovernanceOutcome.SESSION_NOT_ACTIVE, second.outcome());

        // 拿旧刷新凭证再刷也无法"复活"
        assertEquals(AuthOutcome.SESSION_REVOKED, h.authService().refresh(a.tokens().refreshToken()).outcome());
        assertEquals(1, h.governanceService().listSessions("alice", sessionB).sessions().size());
    }

    @Test
    void revokeOthersKeepsCurrentAndKillsTheRest() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult a = login(h, "alice", "password123");
        h.clock().advanceSeconds(1);
        AuthResult b = login(h, "alice", "password123");
        h.clock().advanceSeconds(1);
        AuthResult c = login(h, "alice", "password123");
        String sessionB = h.sessionRepository().findByRefreshToken(b.tokens().refreshToken())
                .orElseThrow().getSessionId();

        // 以中间端 b 为当前，撤销其他 -> a、c 死，b 活
        GovernanceResult result = h.governanceService().revokeOtherSessions("alice", sessionB);
        log.info("CASE revoke-others: outcome={} affected={}", result.outcome(), result.affected());
        assertEquals(GovernanceOutcome.REVOKE_OTHERS_SUCCESS, result.outcome());
        assertEquals(2, result.affected());

        assertEquals(AccessDeniedReason.TOKEN_REVOKED,
                h.accessControlService().decide(a.tokens().accessToken(), "profile:read").deniedReason());
        assertEquals(AccessDeniedReason.TOKEN_REVOKED,
                h.accessControlService().decide(c.tokens().accessToken(), "profile:read").deniedReason());
        assertTrue(h.accessControlService().decide(b.tokens().accessToken(), "profile:read").allowed());

        List<SessionView> remaining = h.governanceService().listSessions("alice", sessionB).sessions();
        assertEquals(1, remaining.size());
        assertEquals(sessionB, remaining.get(0).sessionId());

        // 再执行一次：没有"其他"可撤，affected=0，当前仍活
        GovernanceResult again = h.governanceService().revokeOtherSessions("alice", sessionB);
        assertEquals(0, again.affected());
        assertTrue(h.accessControlService().decide(b.tokens().accessToken(), "profile:read").allowed());
    }

    @Test
    void crossUserViewAndRevocationAreExplicitlyDenied() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult alice = login(h, "alice", "password123");
        AuthResult bob = login(h, "bob", "bob123");
        String aliceSession = h.sessionRepository()
                .findByRefreshToken(alice.tokens().refreshToken()).orElseThrow().getSessionId();
        String bobSession = h.sessionRepository()
                .findByRefreshToken(bob.tokens().refreshToken()).orElseThrow().getSessionId();

        // bob 尝试撤销 alice 的会话：SESSION_NOT_OWNED（HTTP 层映射 403）
        GovernanceResult denied = h.governanceService().revokeSession("bob", bobSession, aliceSession);
        log.info("CASE cross-user revoke: outcome={}", denied.outcome());
        assertEquals(GovernanceOutcome.SESSION_NOT_OWNED, denied.outcome());

        // alice 会话不受影响，bob 列表里看不到 alice 会话
        assertTrue(h.accessControlService()
                .decide(alice.tokens().accessToken(), "profile:read").allowed());
        assertTrue(h.governanceService().listSessions("bob", bobSession).sessions().stream()
                .noneMatch(v -> v.sessionId().equals(aliceSession)));

        // 不存在的会话 ID：NOT_FOUND，而不是 NOT_OWNED（不泄漏存在性之外的信息）
        assertEquals(GovernanceOutcome.SESSION_NOT_FOUND,
                h.governanceService().revokeSession("bob", bobSession, "no-such-id").outcome());
    }

    @Test
    void governanceDecisionsAreAuditedWithKeyInputsAndBasis() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult alice = login(h, "alice", "password123");
        AuthResult bob = login(h, "bob", "bob123");
        String aliceSession = h.sessionRepository()
                .findByRefreshToken(alice.tokens().refreshToken()).orElseThrow().getSessionId();
        String bobSession = h.sessionRepository()
                .findByRefreshToken(bob.tokens().refreshToken()).orElseThrow().getSessionId();

        h.governanceService().listSessions("alice", aliceSession);
        h.governanceService().revokeSession("alice", aliceSession, aliceSession);
        h.governanceService().revokeSession("bob", bobSession, aliceSession);

        var events = h.auditService().snapshot();
        log.info("CASE audit: 治理相关审计条数={}", events.stream()
                .filter(e -> "SESSION_GOVERNANCE".equals(e.action())).count());

        // 列表、成功撤销、越权拒绝都有审计，且 detail 含关键输入（会话 id / 条数）
        assertTrue(events.stream().anyMatch(e ->
                "SESSION_GOVERNANCE".equals(e.action()) && "LIST_SUCCESS".equals(e.result())));
        assertTrue(events.stream().anyMatch(e ->
                "REVOKE_SESSION_SUCCESS".equals(e.result()) && e.detail().contains(aliceSession)));
        var crossAudit = events.stream()
                .filter(e -> "SESSION_NOT_OWNED".equals(e.result())).findFirst();
        assertTrue(crossAudit.isPresent());
        assertTrue(crossAudit.get().detail().contains(aliceSession),
                "越权审计需包含被尝试操作的目标会话 id");
        assertEquals("bob", crossAudit.get().subject());
    }
}
