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
    /** 闲置窗口：刻意短于访问凭证有效期，便于在访问侧观察到 SESSION_IDLE（生产默认 30m）。 */
    public static final Duration IDLE_TTL = Duration.ofMinutes(5);
    /** 每用户活跃会话容量上限（治理测试据此制造超限淘汰）。 */
    public static final int MAX_SESSIONS = 3;

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
                failureTracker, tokenIssuer, clock, auditService,
                ACCESS_TTL, REFRESH_TTL, IDLE_TTL, MAX_SESSIONS);
        AccessControlService accessControlService =
                new AccessControlService(sessionRepository, userDirectory, clock, auditService, IDLE_TTL);
        SessionGovernanceService governanceService =
                new SessionGovernanceService(sessionRepository, clock, auditService, IDLE_TTL);
        return new Harness(clock, authService, accessControlService, governanceService,
                sessionRepository, userDirectory, auditService);
    }
}
