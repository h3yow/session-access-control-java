package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AuthContext;
import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;
import com.github.h3yow.sessionaccesscontroljava.auth.model.Role;
import com.github.h3yow.sessionaccesscontroljava.auth.model.TokenIssued;
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
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 凭证生命周期单测：签发、校验、刷新轮换、重放检测、过期、撤销。
 * 使用可变固定时钟驱动过期场景。每个断言前后打印关键输入与判定依据。
 */
class TokenServiceTest {

    private static final Logger log = LoggerFactory.getLogger(TokenServiceTest.class);

    private MutableClock clock;
    private TokenService tokenService;
    private SessionStore sessionStore;

    static class MutableClock extends Clock {
        volatile Instant instant;

        MutableClock(Instant start) {
            this.instant = start;
        }

        void advanceSeconds(long seconds) {
            instant = instant.plusSeconds(seconds);
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
        clock = new MutableClock(Instant.parse("2026-09-23T00:00:00Z"));
        SecurityProperties props = new SecurityProperties();
        props.setAccessTokenTtlSeconds(10);
        props.setRefreshTokenTtlSeconds(30);
        sessionStore = new SessionStore();
        RefreshTokenStore refreshTokenStore = new RefreshTokenStore();
        AccessTokenStore accessTokenStore = new AccessTokenStore();
        LoginFailureStore loginFailureStore = new LoginFailureStore();
        AuditService auditService = new AuditService(new AuditStore(), clock);
        tokenService = new TokenService(sessionStore, refreshTokenStore, accessTokenStore,
                new TokenHasher(), auditService, props, clock);
    }

    private AtomicReference<DecisionReason> check(TokenIssued t, String label) {
        assertTrue(t.success(), label + " should succeed, reason=" + t.reason());
        log.info("[{}] 签发成功 sessionId={} accessToken={}... refreshToken={}... accessExp={} refreshExp={}",
                label, t.sessionId(),
                abbreviate(t.accessToken()), abbreviate(t.refreshToken()),
                t.accessTokenExpiresAt(), t.refreshTokenExpiresAt());
        return new AtomicReference<>();
    }

    private String abbreviate(String s) {
        return s == null ? "null" : s.substring(0, Math.min(8, s.length())) + "..";
    }

    private AuthContext requireAuth(String accessToken, DecisionReason expected, String label) {
        AtomicReference<DecisionReason> reason = new AtomicReference<>();
        AuthContext ctx = tokenService.authenticateAccessToken(accessToken, reason);
        log.info("[{}] accessToken={} -> reason={} ctxUser={}",
                label, abbreviate(accessToken), reason.get(), ctx != null ? ctx.username() : null);
        assertEquals(expected, reason.get(), label + " reason");
        return ctx;
    }

    @Test
    @DisplayName("登录签发后访问凭证可用，错误/缺失凭证返回未认证")
    void issueAndAuthenticate() {
        TokenIssued t = tokenService.issueForLogin("alice", Set.of(Role.ADMIN));
        check(t, "login");

        AuthContext ctx = requireAuth(t.accessToken(), DecisionReason.ALLOWED, "valid-token");
        assertEquals("alice", ctx.username());

        requireAuth(null, DecisionReason.UNAUTHENTICATED, "null-token");
        requireAuth("not-a-real-token", DecisionReason.UNAUTHENTICATED, "garbage-token");
    }

    @Test
    @DisplayName("刷新轮换：新凭证有效，旧刷新凭证失效，旧访问凭证失效")
    void refreshRotatesTokens() {
        TokenIssued first = tokenService.issueForLogin("bob", Set.of(Role.USER));
        check(first, "first");

        clock.advanceSeconds(1);
        TokenIssued second = tokenService.refresh(first.refreshToken());
        check(second, "refresh-1");
        assertEquals(first.sessionId(), second.sessionId(), "刷新应保持同一会话链");

        // 新访问凭证有效
        requireAuth(second.accessToken(), DecisionReason.ALLOWED, "new-access");
        // 旧访问凭证已被轮换 -> 未认证（不再是当前凭证）
        requireAuth(first.accessToken(), DecisionReason.UNAUTHENTICATED, "old-access-replaced");
        // 旧刷新凭证不能再次成功使用（这里它已 REPLACED -> 触发重放，单独用例断言）
    }

    @Test
    @DisplayName("旧刷新凭证重复使用：返回 REFRESH_TOKEN_REUSED 且整条会话链失效")
    void reuseOfRotatedRefreshTokenInvalidatesChain() {
        TokenIssued first = tokenService.issueForLogin("bob", Set.of(Role.USER));
        TokenIssued second = tokenService.refresh(first.refreshToken());
        check(second, "refresh-ok");

        // 攻击者拿到旧刷新凭证再次使用
        TokenIssued replay = tokenService.refresh(first.refreshToken());
        log.info("[replay] 旧刷新凭证重用 -> success={} reason={} message={}",
                replay.success(), replay.reason(), replay.message());
        assertFalse(replay.success());
        assertEquals(DecisionReason.REFRESH_TOKEN_REUSED, replay.reason(),
                "重放必须返回可区分原因 REFRESH_TOKEN_REUSED");

        // 整链失效：新访问凭证、新刷新凭证都不再可用
        AtomicReference<DecisionReason> r = new AtomicReference<>();
        AuthContext ctx = tokenService.authenticateAccessToken(second.accessToken(), r);
        log.info("[replay] 链撤销后新访问凭证 -> reason={}", r.get());
        assertNull(ctx);
        assertEquals(DecisionReason.REVOKED, r.get(), "整链撤销后访问凭证应判定为 REVOKED");

        TokenIssued third = tokenService.refresh(second.refreshToken());
        log.info("[replay] 链撤销后新刷新凭证 -> reason={}", third.reason());
        assertFalse(third.success());
        assertEquals(DecisionReason.REVOKED, third.reason(), "链上当前刷新凭证应已被撤销");

        assertTrue(sessionStore.find(first.sessionId()).orElseThrow().isRevoked(),
                "会话链最终必须收敛为已撤销");
    }

    @Test
    @DisplayName("未知刷新凭证返回 TOKEN_UNKNOWN，与重放原因可区分")
    void unknownRefreshToken() {
        TokenIssued r = tokenService.refresh("deadbeef");
        log.info("[unknown] reason={}", r.reason());
        assertFalse(r.success());
        assertEquals(DecisionReason.TOKEN_UNKNOWN, r.reason());
    }

    @Test
    @DisplayName("访问凭证与刷新凭证过期分别返回 EXPIRED")
    void expiredTokens() {
        TokenIssued first = tokenService.issueForLogin("carol", Set.of(Role.GUEST));

        // 访问凭证过期（刷新凭证尚未过期）
        clock.advanceSeconds(11);
        requireAuth(first.accessToken(), DecisionReason.EXPIRED, "access-expired");

        TokenIssued stillRefresh = tokenService.refresh(first.refreshToken());
        check(stillRefresh, "refresh-within-ttl");

        // 刷新凭证过期
        clock.advanceSeconds(31);
        TokenIssued expired = tokenService.refresh(stillRefresh.refreshToken());
        log.info("[refresh-expired] reason={}", expired.reason());
        assertFalse(expired.success());
        assertEquals(DecisionReason.EXPIRED, expired.reason());
    }

    @Test
    @DisplayName("主动撤销后访问与刷新均判定 REVOKED，撤销幂等")
    void activeRevocation() {
        TokenIssued first = tokenService.issueForLogin("alice", Set.of(Role.ADMIN));

        boolean ok1 = tokenService.revokeSession(first.sessionId(), "alice");
        boolean ok2 = tokenService.revokeSession(first.sessionId(), "alice");
        log.info("[revoke] first={} second(幂等)={}", ok1, ok2);
        assertTrue(ok1);
        assertTrue(ok2);

        requireAuth(first.accessToken(), DecisionReason.REVOKED, "access-after-revoke");
        TokenIssued r = tokenService.refresh(first.refreshToken());
        assertEquals(DecisionReason.REVOKED, r.reason(), "revoked refresh token -> REVOKED");
    }

    @Test
    @DisplayName("同一刷新凭证并发刷新：至多一条成功，链状态收敛，不产生两条有效链")
    void concurrentRefreshProducesSingleChain() throws Exception {
        TokenIssued first = tokenService.issueForLogin("bob", Set.of(Role.USER));
        String refresh = first.refreshToken();

        int threads = 16;
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
        java.util.List<java.util.concurrent.Future<TokenIssued>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return tokenService.refresh(refresh);
            }));
        }
        start.countDown();

        int success = 0;
        int reused = 0;
        int revoked = 0;
        TokenIssued theSuccess = null;
        for (var f : futures) {
            TokenIssued r = f.get();
            if (r.success()) {
                success++;
                theSuccess = r;
            } else if (r.reason() == DecisionReason.REFRESH_TOKEN_REUSED) {
                reused++;
            } else if (r.reason() == DecisionReason.REVOKED) {
                revoked++;
            }
        }
        pool.shutdown();
        log.info("[concurrent-refresh] threads={} success={} reused={} revoked={}",
                threads, success, reused, revoked);

        assertTrue(success <= 1, "同一凭证并发刷新至多一次成功，实际成功=" + success);

        // 最终链状态必须收敛：要么正常存活（恰好一次成功），要么因重放检测被整体撤销
        var chain = sessionStore.find(first.sessionId()).orElseThrow();
        log.info("[concurrent-refresh] final chain revoked={} version={} reason={}",
                chain.isRevoked(), chain.getRotationVersion(), chain.getRevokeReason());
        if (!chain.isRevoked()) {
            assertEquals(1, success, "链存活时必须恰好一次刷新成功");
            assertEquals(2, chain.getRotationVersion(), "版本号应只前进一次");
        } else {
            // 重放检测是整链失效（family breach 语义）：
            // 即便某线程在此之前先一步成功，其刚签发的凭证也必须随链一起失效，
            // 因而绝不会存在“两条同时有效的链”，最终收敛为无有效凭证。
            assertEquals(DecisionReason.REFRESH_TOKEN_REUSED, chain.getRevokeReason(),
                    "并发中被判定重放时撤销原因必须可区分");
            assertTrue(reused >= 1, "链被撤销必然由至少一次重放判定触发");
            if (theSuccess != null) {
                AtomicReference<DecisionReason> after = new AtomicReference<>();
                AuthContext ctx = tokenService.authenticateAccessToken(theSuccess.accessToken(), after);
                log.info("[concurrent-refresh] 先成功后随链撤销的访问凭证 -> reason={}", after.get());
                assertNull(ctx, "重放整链失效后，先成功的凭证也不得继续有效");
                assertEquals(DecisionReason.REVOKED, after.get());
            }
        }
    }
}
