package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.access.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDeniedReason;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 覆盖：未认证（无凭证/未知凭证）、已过期、已撤销、权限不足、默认拒绝、
 * 以及基于角色/细粒度权限的放行，所有拒绝原因彼此可区分。
 */
class AccessControlTests {

    private static final Logger log = LoggerFactory.getLogger(AccessControlTests.class);

    @Test
    void allDenialReasonsAreDistinguishable() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String access = login.tokens().accessToken();

        AccessDecision missing = h.accessControlService().decide(null, "profile:read");
        AccessDecision unknown = h.accessControlService().decide("made-up-token", "profile:read");
        AccessDecision expired = expiredDecision(h, access);
        AccessDecision revoked = revokedDecision(h);

        log.info("CASE reasons: missing={} unknown={} expired={} revoked={}",
                missing.deniedReason(), unknown.deniedReason(),
                expired.deniedReason(), revoked.deniedReason());
        assertEquals(AccessDeniedReason.MISSING_CREDENTIAL, missing.deniedReason());
        assertEquals(AccessDeniedReason.UNKNOWN_TOKEN, unknown.deniedReason());
        assertEquals(AccessDeniedReason.TOKEN_EXPIRED, expired.deniedReason());
        assertEquals(AccessDeniedReason.TOKEN_REVOKED, revoked.deniedReason());
    }

    private AccessDecision expiredDecision(TestFixtures.Harness h, String access) {
        h.clock().advance(TestFixtures.ACCESS_TTL.plusSeconds(1));
        return h.accessControlService().decide(access, "profile:read");
    }

    private AccessDecision revokedDecision(TestFixtures.Harness h) {
        AuthResult login = h.authService().login("bob", "bob123");
        String access = login.tokens().accessToken();
        h.authService().revoke(login.tokens().refreshToken());
        return h.accessControlService().decide(access, "profile:read");
    }

    @Test
    void roleBasedAllowAndInsufficientPermissionAreDistinguishable() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult aliceLogin = h.authService().login("alice", "password123");
        String aliceAccess = aliceLogin.tokens().accessToken();

        AccessDecision profile = h.accessControlService().decide(aliceAccess, "profile:read");
        AccessDecision admin = h.accessControlService().decide(aliceAccess, "admin:read");
        AccessDecision finance = h.accessControlService().decide(aliceAccess, "finance:read");
        log.info("CASE alice: profile allowed={}, admin reason={}, finance reason={}",
                profile.allowed(), admin.deniedReason(), finance.deniedReason());
        assertTrue(profile.allowed());
        assertEquals(AccessDeniedReason.INSUFFICIENT_PERMISSION, admin.deniedReason());
        assertEquals(AccessDeniedReason.INSUFFICIENT_PERMISSION, finance.deniedReason());

        AuthResult adminLogin = h.authService().login("admin", "admin123");
        AccessDecision adminOk = h.accessControlService()
                .decide(adminLogin.tokens().accessToken(), "admin:read");
        AccessDecision adminFinance = h.accessControlService()
                .decide(adminLogin.tokens().accessToken(), "finance:read");
        log.info("CASE admin: admin allowed={}, finance reason={}",
                adminOk.allowed(), adminFinance.deniedReason());
        assertTrue(adminOk.allowed());
        assertEquals(AccessDeniedReason.INSUFFICIENT_PERMISSION, adminFinance.deniedReason());

        AuthResult bobLogin = h.authService().login("bob", "bob123");
        AccessDecision financeOk = h.accessControlService()
                .decide(bobLogin.tokens().accessToken(), "finance:read");
        log.info("CASE bob: finance allowed={}", financeOk.allowed());
        assertTrue(financeOk.allowed());
    }

    @Test
    void undeclaredPermissionDefaultsToDeny() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("admin", "admin123");
        AccessDecision decision = h.accessControlService().decide(login.tokens().accessToken(), null);
        log.info("CASE default-deny: reason={} message={}", decision.deniedReason(), decision.message());
        assertFalse(decision.allowed());
        assertEquals(AccessDeniedReason.INSUFFICIENT_PERMISSION, decision.deniedReason());
    }
}
