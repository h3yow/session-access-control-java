package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.audit.AuditService;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthService;
import com.github.h3yow.sessionaccesscontroljava.auth.LoginFailureTracker;
import com.github.h3yow.sessionaccesscontroljava.auth.PasswordHasher;
import com.github.h3yow.sessionaccesscontroljava.auth.AppUser;
import com.github.h3yow.sessionaccesscontroljava.auth.UserDirectory;
import com.github.h3yow.sessionaccesscontroljava.access.AccessControlService;
import com.github.h3yow.sessionaccesscontroljava.governance.SessionGovernanceService;
import com.github.h3yow.sessionaccesscontroljava.session.SessionRepository;
import com.github.h3yow.sessionaccesscontroljava.token.TokenIssuer;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/** 构造一套与生产一致、但使用可控时钟与短 TTL 的服务组件，供单元测试直接调用。 */
public final class TestFixtures {

    public static final Duration ACCESS_TTL = Duration.ofMinutes(15);
    public static final Duration REFRESH_TTL = Duration.ofHours(12);
    /** 测试默认闲置超时：30 分钟无访问/刷新即自动失效。 */
    public static final Duration IDLE_TIMEOUT = Duration.ofMinutes(30);
    /** 测试默认单用户活跃会话容量上限。 */
    public static final int MAX_SESSIONS_PER_USER = 5;

    private TestFixtures() {
    }

    public record Harness(
            MutableTickClock clock,
            AuthService authService,
            AccessControlService accessControlService,
            SessionGovernanceService governanceService,
            SessionRepository sessionRepository,
            UserDirectory userDirectory,
            AuditService auditService) {
    }

    public static Harness newHarness() {
        return newHarness(IDLE_TIMEOUT, MAX_SESSIONS_PER_USER);
    }

    public static Harness newHarness(Duration idleTimeout, int maxSessionsPerUser) {
        return newHarness(ACCESS_TTL, REFRESH_TTL, idleTimeout, maxSessionsPerUser);
    }

    /**
     * 构造一套与生产一致的组件，但四个时间/容量参数全部可控：
     * 绝对过期专项用例用它把 accessTtl 调到接近 refreshTtl 或 idleTimeout，
     * 从而精确复现"绝对有效期先到、访问凭证表面未到期、闲置窗口还没到"等组合。
     */
    public static Harness newHarness(Duration accessTtl, Duration refreshTtl,
                                     Duration idleTimeout, int maxSessionsPerUser) {
        MutableTickClock clock = new MutableTickClock(Instant.parse("2026-09-23T00:00:00Z"));
        SessionRepository sessionRepository = new SessionRepository();
        UserDirectory userDirectory = new UserDirectory();
        PasswordHasher passwordHasher = new PasswordHasher();
        userDirectory.register(new AppUser("alice", passwordHasher.hash("password123"),
                Set.of("ROLE_USER"), Set.of()));
        userDirectory.register(new AppUser("admin", passwordHasher.hash("admin123"),
                Set.of("ROLE_ADMIN"), Set.of()));
        userDirectory.register(new AppUser("bob", passwordHasher.hash("bob123"),
                Set.of("ROLE_FINANCE"), Set.of()));
        LoginFailureTracker failureTracker = new LoginFailureTracker(clock, 5, Duration.ofMinutes(5));
        TokenIssuer tokenIssuer = new TokenIssuer();
        AuditService auditService = new AuditService(clock);
        AuthService authService = new AuthService(sessionRepository, userDirectory, passwordHasher,
                failureTracker, tokenIssuer, clock, auditService, accessTtl, refreshTtl,
                idleTimeout, maxSessionsPerUser);
        AccessControlService accessControlService =
                new AccessControlService(sessionRepository, userDirectory, clock, auditService, idleTimeout);
        SessionGovernanceService governanceService =
                new SessionGovernanceService(sessionRepository, clock, auditService, idleTimeout, maxSessionsPerUser);
        return new Harness(clock, authService, accessControlService, governanceService, sessionRepository,
                userDirectory, auditService);
    }
}
