package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AccessDecision;
import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;
import com.github.h3yow.sessionaccesscontroljava.auth.model.Role;
import com.github.h3yow.sessionaccesscontroljava.auth.model.TokenIssued;
import com.github.h3yow.sessionaccesscontroljava.auth.security.AccessGuard;
import com.github.h3yow.sessionaccesscontroljava.auth.security.AuditService;
import com.github.h3yow.sessionaccesscontroljava.auth.security.TokenHasher;
import com.github.h3yow.sessionaccesscontroljava.auth.security.TokenService;
import com.github.h3yow.sessionaccesscontroljava.auth.store.AccessTokenStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.AuditStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.LoginFailureStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.RefreshTokenStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.SessionStore;
import com.github.h3yow.sessionaccesscontroljava.config.SecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 访问控制守卫单测：四类拒绝原因可区分、默认拒绝、角色权限聚合。
 */
class AccessGuardTest {

    private static final Logger log = LoggerFactory.getLogger(AccessGuardTest.class);

    private MutableClock clock;
    private AccessGuard guard;
    private TokenService tokenService;

    static class MutableClock extends Clock {
        volatile Instant instant = Instant.parse("2026-09-23T00:00:00Z");

        void advanceSeconds(long s) {
            instant = instant.plusSeconds(s);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        SecurityProperties props = new SecurityProperties();
        props.setAccessTokenTtlSeconds(10);
        props.setRefreshTokenTtlSeconds(60);
        SessionStore sessionStore = new SessionStore();
        AuditService auditService = new AuditService(new AuditStore(), clock);
        tokenService = new TokenService(sessionStore, new RefreshTokenStore(),
                new AccessTokenStore(), new TokenHasher(), auditService, props, clock);
        guard = new AccessGuard(tokenService, auditService);
    }

    private void assertDeny(String header, String permission, DecisionReason expected, String label) {
        AccessDecision d = guard.decide(header, permission);
        log.info("[{}] permission={} -> allowed={} reason={} message={}",
                label, permission, d.allowed(), d.reason(), d.message());
        assertFalse(d.allowed());
        assertEquals(expected, d.reason());
        assertNull(d.context());
    }

    private String bearer(TokenIssued t) {
        return "Bearer " + t.accessToken();
    }

    @Test
    @DisplayName("无凭证 / 无法识别凭证 -> UNAUTHENTICATED")
    void unauthenticated() {
        assertDeny(null, "profile:read", DecisionReason.UNAUTHENTICATED, "no-header");
        assertDeny("Bearer garbage", "profile:read", DecisionReason.UNAUTHENTICATED, "garbage");
        assertDeny("Basic abc", "profile:read", DecisionReason.UNAUTHENTICATED, "wrong-scheme");
    }

    @Test
    @DisplayName("访问凭证过期 -> EXPIRED，可与未认证区分")
    void expired() {
        TokenIssued t = tokenService.issueForLogin("bob", Set.of(Role.USER));
        clock.advanceSeconds(11);
        assertDeny(bearer(t), "profile:read", DecisionReason.EXPIRED, "expired");
    }

    @Test
    @DisplayName("会话撤销后访问 -> REVOKED，可与过期/未认证区分")
    void revoked() {
        TokenIssued t = tokenService.issueForLogin("bob", Set.of(Role.USER));
        tokenService.revokeSession(t.sessionId(), "tester");
        assertDeny(bearer(t), "profile:read", DecisionReason.REVOKED, "revoked");
    }

    @Test
    @DisplayName("权限不足 -> INSUFFICIENT_PERMISSION（403 语义），认证成功但授权失败")
    void insufficientPermission() {
        TokenIssued t = tokenService.issueForLogin("bob", Set.of(Role.USER));
        assertDeny(bearer(t), "admin:read", DecisionReason.INSUFFICIENT_PERMISSION, "user-to-admin");

        TokenIssued guest = tokenService.issueForLogin("carol", Set.of(Role.GUEST));
        assertDeny(bearer(guest), "profile:read", DecisionReason.INSUFFICIENT_PERMISSION, "guest-to-profile");
    }

    @Test
    @DisplayName("具备所需权限 -> ALLOWED，角色权限聚合正确")
    void allowed() {
        TokenIssued admin = tokenService.issueForLogin("alice", Set.of(Role.ADMIN));
        for (String p : new String[]{"profile:read", "admin:read", "admin:write"}) {
            AccessDecision d = guard.decide(bearer(admin), p);
            log.info("[allow-admin] permission={} -> allowed={} reason={}", p, d.allowed(), d.reason());
            assertTrue(d.allowed(), "ADMIN 应拥有 " + p);
            assertNotNull(d.context());
            assertEquals("alice", d.context().username());
        }

        TokenIssued user = tokenService.issueForLogin("bob", Set.of(Role.USER));
        AccessDecision d = guard.decide(bearer(user), "profile:read");
        assertTrue(d.allowed());
    }

    @Test
    @DisplayName("重放导致整链撤销后，原访问凭证 -> REVOKED 而非 EXPIRED/UNAUTHENTICATED")
    void replayRevokesAccess() {
        TokenIssued first = tokenService.issueForLogin("bob", Set.of(Role.USER));
        TokenIssued second = tokenService.refresh(first.refreshToken());
        assertTrue(second.success());
        TokenIssued replay = tokenService.refresh(first.refreshToken());
        assertEquals(DecisionReason.REFRESH_TOKEN_REUSED, replay.reason());

        assertDeny(bearer(second), "profile:read", DecisionReason.REVOKED, "access-after-replay");
    }
}
