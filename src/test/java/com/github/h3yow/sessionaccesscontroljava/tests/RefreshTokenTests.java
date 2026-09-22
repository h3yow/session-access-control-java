package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import com.github.h3yow.sessionaccesscontroljava.session.SessionChain;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 覆盖：刷新轮换、旧 refresh 凭证重复使用 -> 整条链失效且原因可区分、
 * 刷新后旧访问凭证同时失效。
 */
class RefreshTokenTests {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenTests.class);

    private AuthResult loginAlice(TestFixtures.Harness h) {
        AuthResult login = h.authService().login("alice", "password123");
        assertEquals(AuthOutcome.LOGIN_SUCCESS, login.outcome());
        return login;
    }

    @Test
    void refreshRotatesAndInvalidatesOldRefreshToken() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = loginAlice(h);
        String oldRefresh = login.tokens().refreshToken();
        log.info("CASE rotate: 输入 oldRefreshPrefix={}", oldRefresh.substring(0, 6));

        AuthResult refreshed = h.authService().refresh(oldRefresh);
        log.info("CASE rotate: 判定 outcome={}, 新refreshPrefix={}",
                refreshed.outcome(), refreshed.tokens().refreshToken().substring(0, 6));
        assertEquals(AuthOutcome.REFRESH_SUCCESS, refreshed.outcome());
        assertNotEquals(oldRefresh, refreshed.tokens().refreshToken());

        // 旧凭证再次使用：必须被识别为复用，而不是"unknown"或再次成功
        AuthResult reuse = h.authService().refresh(oldRefresh);
        log.info("CASE reuse: 输入 oldRefreshPrefix={} 判定 outcome={} message={}",
                oldRefresh.substring(0, 6), reuse.outcome(), reuse.message());
        assertEquals(AuthOutcome.REFRESH_TOKEN_REUSED, reuse.outcome());

        // 会话链整体失效：新凭证同样无法再刷新
        String newRefresh = refreshed.tokens().refreshToken();
        AuthResult afterReuse = h.authService().refresh(newRefresh);
        log.info("CASE after-reuse: 输入 currentRefreshPrefix={} 判定 outcome={}",
                newRefresh.substring(0, 6), afterReuse.outcome());
        assertEquals(AuthOutcome.SESSION_REVOKED, afterReuse.outcome());

        Optional<SessionChain> chain = h.sessionRepository().findByRefreshToken(newRefresh);
        assertTrue(chain.isPresent());
        assertEquals(SessionState.REVOKED, chain.get().getState());
    }

    @Test
    void reuseAlsoRevokesAccessTokensIssuedBefore() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult login = loginAlice(h);
        String firstAccess = login.tokens().accessToken();

        AuthResult refreshed = h.authService().refresh(login.tokens().refreshToken());
        String secondAccess = refreshed.tokens().accessToken();
        log.info("CASE reuse-revoke-access: firstAccess={} secondAccess={}",
                firstAccess.substring(0, 6), secondAccess.substring(0, 6));

        // 复用旧 refresh -> 链撤销
        assertEquals(AuthOutcome.REFRESH_TOKEN_REUSED,
                h.authService().refresh(login.tokens().refreshToken()).outcome());

        // 撤销级联到该会话全部访问凭证（含刷新前签发的）
        assertTrue(h.sessionRepository().findAccessRecord(firstAccess).orElseThrow().isRevoked());
        assertTrue(h.sessionRepository().findAccessRecord(secondAccess).orElseThrow().isRevoked());
        log.info("CASE reuse-revoke-access: 全部访问凭证 revoked=true，状态收敛");
    }

    @Test
    void unknownRefreshTokenHasDistinctReason() {
        TestFixtures.Harness h = TestFixtures.newHarness();
        AuthResult result = h.authService().refresh("definitely-not-a-real-token");
        log.info("CASE unknown: 判定 outcome={}", result.outcome());
        assertEquals(AuthOutcome.REFRESH_TOKEN_UNKNOWN, result.outcome());
    }
}
