package com.github.h3yow.sessionaccesscontroljava.access;

import com.github.h3yow.sessionaccesscontroljava.audit.AuditService;
import com.github.h3yow.sessionaccesscontroljava.auth.AppUser;
import com.github.h3yow.sessionaccesscontroljava.auth.UserDirectory;
import com.github.h3yow.sessionaccesscontroljava.clock.TickClock;
import com.github.h3yow.sessionaccesscontroljava.session.AccessRecord;
import com.github.h3yow.sessionaccesscontroljava.session.SessionChain;
import com.github.h3yow.sessionaccesscontroljava.session.SessionRepository;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * 访问控制服务。
 *
 * 判定顺序（短路，每一步都产生可区分原因，任何一项不通过都不得静默放行）：
 * 1. 凭证是否携带        -> MISSING_CREDENTIAL
 * 2. 凭证是否可识别      -> UNKNOWN_TOKEN
 * 3. 凭证是否已撤销      -> TOKEN_REVOKED
 * 4. 凭证是否已过期      -> TOKEN_EXPIRED（短期访问凭证自身自然到期）
 * 5. 会话链生命周期      -> SESSION_REVOKED / SESSION_EXPIRED（长期凭证绝对到期）/
 *                          SESSION_IDLE_TIMEOUT / SESSION_EVICTED
 * 6. 是否显式声明所需权限（默认拒绝）
 * 7. 用户角色/权限是否满足 -> INSUFFICIENT_PERMISSION
 * 注意：会话绝对过期不级联撤销访问凭证，因此第 4 步与第 5 步的原因始终可区分：
 * 访问凭证自身到期 -> TOKEN_EXPIRED；会话长期凭证到点（即使访问凭证表面未到期）-> SESSION_EXPIRED。
 */
@Service
public class AccessControlService {

    private static final Logger log = LoggerFactory.getLogger(AccessControlService.class);

    /** 角色到权限的显式映射：角色不隐式放行任何资源，只展开为明确权限。 */
    private static final Map<String, Set<String>> ROLE_PERMISSIONS = Map.of(
            "ROLE_USER", Set.of("profile:read", "session:manage"),
            "ROLE_ADMIN", Set.of("profile:read", "admin:read", "session:manage"),
            "ROLE_FINANCE", Set.of("profile:read", "finance:read", "session:manage")
    );

    private final SessionRepository sessionRepository;
    private final UserDirectory userDirectory;
    private final TickClock clock;
    private final AuditService auditService;
    private final Duration idleTimeout;

    public AccessControlService(SessionRepository sessionRepository,
                                UserDirectory userDirectory,
                                TickClock clock,
                                AuditService auditService,
                                @Value("${auth.session.idle-timeout:PT30M}") Duration idleTimeout) {
        this.sessionRepository = sessionRepository;
        this.userDirectory = userDirectory;
        this.clock = clock;
        this.auditService = auditService;
        this.idleTimeout = idleTimeout;
    }

    public AccessDecision decide(String accessToken, String requiredPermission) {
        log.info("access-decision-attempt tokenPrefix={} requiredPermission={}", prefix(accessToken), requiredPermission);

        if (accessToken == null || accessToken.isBlank()) {
            return deny(null, AccessDeniedReason.MISSING_CREDENTIAL, "missing access token");
        }

        Optional<AccessRecord> recordOpt = sessionRepository.findAccessRecord(accessToken);
        if (recordOpt.isEmpty()) {
            return deny(prefix(accessToken), AccessDeniedReason.UNKNOWN_TOKEN, "unrecognized access token");
        }
        AccessRecord record = recordOpt.get();

        if (record.isRevoked()) {
            return deny(record.getUsername(), AccessDeniedReason.TOKEN_REVOKED,
                    "access token revoked sessionId=" + record.getSessionId());
        }
        if (clock.now().isAfter(record.getExpiresAt())) {
            return deny(record.getUsername(), AccessDeniedReason.TOKEN_EXPIRED,
                    "access token expired at " + record.getExpiresAt());
        }

        Optional<SessionChain> chainOpt = sessionRepository.findById(record.getSessionId());
        if (chainOpt.isEmpty()) {
            return deny(record.getUsername(), AccessDeniedReason.SESSION_REVOKED,
                    "session not found sessionId=" + record.getSessionId());
        }
        SessionChain chain = chainOpt.get();

        // 会话终态判定在 user -> chain 固定加锁顺序下完成（与刷新、名单、容量治理一致）：
        // 同一用户的"名单收敛 / 访问判定 / 刷新轮换 / 撤销 / 淘汰"互斥，
        // 因此在绝对到期点前后并发时，不会出现名单显示存活而访问已拒绝的矛盾。
        // 生命周期懒收敛同时覆盖绝对过期与闲置，且绝对过期优先于闲置。
        synchronized (sessionRepository.userLock(chain.getUsername())) {
            synchronized (chain) {
                SessionState state = sessionRepository.evaluateLifecycle(chain, clock.now(), idleTimeout);
                switch (state) {
                    case REVOKED -> {
                        return deny(record.getUsername(), AccessDeniedReason.SESSION_REVOKED,
                                "session revoked sessionId=" + record.getSessionId());
                    }
                    case IDLE_TIMEOUT -> {
                        return deny(record.getUsername(), AccessDeniedReason.SESSION_IDLE_TIMEOUT,
                                "session idle-timed-out at lastActivityAt=" + chain.getLastActivityAt()
                                        + " sessionId=" + record.getSessionId());
                    }
                    case EVICTED -> {
                        return deny(record.getUsername(), AccessDeniedReason.SESSION_EVICTED,
                                "session evicted by capacity limit sessionId=" + record.getSessionId());
                    }
                    case EXPIRED -> {
                        return deny(record.getUsername(), AccessDeniedReason.SESSION_EXPIRED,
                                "session refresh credential reached absolute expiry at "
                                        + chain.getRefreshTokenExpiresAt()
                                        + " sessionId=" + record.getSessionId());
                    }
                    case ACTIVE -> {
                        // 继续后续权限判定（仍持有链监视器，期间任何终态流转都被阻塞）
                    }
                }

                // 默认拒绝：调用方必须显式声明所需权限
                if (requiredPermission == null || requiredPermission.isBlank()) {
                    return deny(record.getUsername(), AccessDeniedReason.INSUFFICIENT_PERMISSION,
                            "no required permission declared; default-deny sessionId=" + record.getSessionId());
                }

                Optional<AppUser> userOpt = userDirectory.findByUsername(record.getUsername());
                if (userOpt.isEmpty()) {
                    return deny(record.getUsername(), AccessDeniedReason.INSUFFICIENT_PERMISSION,
                            "principal no longer exists; default-deny");
                }
                AppUser user = userOpt.get();
                Set<String> effective = effectivePermissions(user);
                if (!effective.contains(requiredPermission)) {
                    return deny(user.username(), AccessDeniedReason.INSUFFICIENT_PERMISSION,
                            "permission '" + requiredPermission + "' not held; roles=" + user.roles()
                                    + " permissions=" + user.permissions());
                }

                // 访问即活动：仅在凭证与权限全部通过、且会话仍为 ACTIVE 时推进最近活动时间。
                // 绝对过期/终态会话绝不可能走到这里，故不存在"请求把失效会话重新用活"的路径。
                sessionRepository.touchActivity(chain, clock.now());
                log.info("access-granted username={} sessionId={} permission={}",
                        user.username(), record.getSessionId(), requiredPermission);
                auditService.record("ACCESS", user.username(), "ALLOWED",
                        "permission=" + requiredPermission + " sessionId=" + record.getSessionId());
                return AccessDecision.allow(user.username(), record.getSessionId());
            }
        }
    }

    private AccessDecision deny(String subject, AccessDeniedReason reason, String detail) {
        log.warn("access-denied subject={} reason={} detail={}", subject, reason, detail);
        auditService.record("ACCESS", String.valueOf(subject), reason.name(), detail);
        return AccessDecision.deny(reason, detail);
    }

    private Set<String> effectivePermissions(AppUser user) {
        Set<String> all = new LinkedHashSet<>(user.permissions());
        for (String role : user.roles()) {
            Set<String> mapped = ROLE_PERMISSIONS.get(role);
            if (mapped != null) {
                all.addAll(mapped);
            }
        }
        return all;
    }

    /** 测试辅助：查看角色展开结果。 */
    public static Map<String, Set<String>> rolePermissions() {
        return new LinkedHashMap<>(ROLE_PERMISSIONS);
    }

    private static String prefix(String token) {
        if (token == null || token.length() < 6) {
            return "n/a";
        }
        return token.substring(0, 6) + "…";
    }
}
