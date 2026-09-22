package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.access.AccessControlService;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.access.AccessDeniedReason;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

/** 覆盖：访问凭证过期、刷新凭证过期、主动撤销后访问与刷新均被拒绝，且原因可区分。 */
class ExpiryAndRevocationTests {

    private static final Logger log = LoggerFactory.getLogger(ExpiryAndRevocationTests.class);

    @Test
    void expiredAccessTokenIsRejectedWithDistinctReason() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String access = login.tokens().accessToken();
        log.info("CASE access-expired: accessExpiresAt={}", login.tokens().accessTokenExpiresAt());

        AccessDecision before = h.accessControlService().decide(access, "profile:read");
        assertTrue(before.allowed());

        h.clock().advance(TestFixtures.ACCESS_TTL.plusSeconds(1));
        AccessDecision after = h.accessControlService().decide(access, "profile:read");
        log.info("CASE access-expired: 推进时间 15m+1s -> allowed={} reason={} message={}",
                after.allowed(), after.deniedReason(), after.message());
        assertFalse(after.allowed());
        assertEquals(AccessDeniedReason.TOKEN_EXPIRED, after.deniedReason());
    }

    @Test
    void expiredRefreshTokenIsRejectedWithDistinctReason() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");

        h.clock().advance(TestFixtures.REFRESH_TTL.plusSeconds(1));
        AuthResult result = h.authService().refresh(login.tokens().refreshToken());
        log.info("CASE refresh-expired: 推进时间 12h+1s -> outcome={}", result.outcome());
        assertEquals(AuthOutcome.REFRESH_TOKEN_EXPIRED, result.outcome());
    }

    @Test
    void activeRevocationKillsSessionAndAllAccessTokens() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = h.authService().login("alice", "password123");
        String access1 = login.tokens().accessToken();
        String refresh = login.tokens().refreshToken();

        AuthResult refreshed = h.authService().refresh(refresh);
        assertEquals(AuthOutcome.REFRESH_SUCCESS, refreshed.outcome());
        String access2 = refreshed.tokens().accessToken();
        String currentRefresh = refreshed.tokens().refreshToken();

        AuthResult revoke = h.authService().revoke(currentRefresh);
        log.info("CASE revoke: outcome={}", revoke.outcome());
        assertEquals(AuthOutcome.REVOKE_SUCCESS, revoke.outcome());

        AccessDecision d1 = h.accessControlService().decide(access1, "profile:read");
        AccessDecision d2 = h.accessControlService().decide(access2, "profile:read");
        log.info("CASE revoke: access1 -> reason={}; access2 -> reason={}",
                d1.deniedReason(), d2.deniedReason());
        assertEquals(AccessDeniedReason.TOKEN_REVOKED, d1.deniedReason());
        assertEquals(AccessDeniedReason.TOKEN_REVOKED, d2.deniedReason());

        AuthResult refreshAfterRevoke = h.authService().refresh(currentRefresh);
        log.info("CASE revoke: refresh -> outcome={}", refreshAfterRevoke.outcome());
        assertEquals(AuthOutcome.SESSION_REVOKED, refreshAfterRevoke.outcome());
    }

    @Test
    void revokeUnknownTokenHasDistinctOutcome() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult result = h.authService().revoke("no-such-token");
        assertEquals(AuthOutcome.REVOKE_NOT_FOUND, result.outcome());
        log.info("CASE revoke-unknown: outcome={}", result.outcome());
    }
}
