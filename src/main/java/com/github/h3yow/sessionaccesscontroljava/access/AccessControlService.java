package com.github.h3yow.sessionaccesscontroljava.access;

import com.github.h3yow.sessionaccesscontroljava.audit.AuditService;
import com.github.h3yow.sessionaccesscontroljava.auth.AppUser;
import com.github.h3yow.sessionaccesscontroljava.auth.UserDirectory;
import com.github.h3yow.sessionaccesscontroljava.clock.TickClock;
import com.github.h3yow.sessionaccesscontroljava.session.AccessRecord;
import com.github.h3yow.sessionaccesscontroljava.session.AccessRevokeReason;
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
 * 3. 访问凭证自身是否过期 -> TOKEN_EXPIRED（绝对过期，先于会话级原因）
 * 4. 凭证是否因会话终止被级联撤销（区分撤销/闲置/淘汰）
 *    TOKEN_REVOKED / SESSION_IDLE / SESSION_EVICTED
 * 5. 所属会话链是否仍存活（惰性识别闲置/绝对过期/已撤销）
 *    SESSION_REVOKED / SESSION_IDLE / SESSION_EVICTED / SESSION_EXPIRED
 * 6. 是否显式声明所需权限（默认拒绝）
 * 7. 用户角色/权限是否满足 -> INSUFFICIENT_PERMISSION
 *
 * 放行时在用户监视器内推进会话"最近活动时间"，使闲置治理与正在进行的刷新/淘汰计数一致。
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
    private final Duration idleTtl;

    public AccessControlService(SessionRepository sessionRepository,
                                UserDirectory userDirectory,
                                TickClock clock,
                                AuditService auditService,
                                @Value("${auth.session.idle-ttl:PT30M}") Duration idleTtl) {
        this.sessionRepository = sessionRepository;
        this.userDirectory = userDirectory;
        this.clock = clock;
        this.auditService = auditService;
        this.idleTtl = idleTtl;
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

        // 访问凭证自身的绝对过期优先（独立于会话闲置/淘汰原因）
        if (clock.now().isAfter(record.getExpiresAt())) {
            return deny(record.getUsername(), AccessDeniedReason.TOKEN_EXPIRED,
                    "access token expired at " + record.getExpiresAt());
        }

        if (record.isRevoked()) {
            return deny(record.getUsername(), denyReasonFor(record.getRevokeReason()),
                    "access token not usable: " + record.getRevokeReason()
                            + " sessionId=" + record.getSessionId());
        }

        Optional<SessionChain> chainOpt = sessionRepository.findById(record.getSessionId());
        if (chainOpt.isEmpty()) {
            return deny(record.getUsername(), AccessDeniedReason.SESSION_REVOKED,
                    "session not found sessionId=" + record.getSessionId());
        }
        SessionChain chain = chainOpt.get();

        SessionState state;
        synchronized (sessionRepository.userLock(record.getUsername())) {
            state = sessionRepository.settleTimeBasedState(chain, clock.now(), idleTtl);
            if (state != SessionState.ACTIVE) {
                return denyForState(record, state);
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

        // 放行：这是一次有效活动，推进最近活动时间（用户监视器内，与刷新/淘汰串行）
        synchronized (sessionRepository.userLock(record.getUsername())) {
            if (sessionRepository.settleTimeBasedState(chain, clock.now(), idleTtl) != SessionState.ACTIVE) {
                // 临界区之间状态可能被并发终止/淘汰，再次确认，绝不静默放行
                return denyForState(record, chain.getState());
            }
            sessionRepository.touch(chain, clock.now());
        }

        log.info("access-granted username={} sessionId={} permission={} lastActivityAt={}",
                user.username(), record.getSessionId(), requiredPermission, chain.getLastActivityAt());
        auditService.record("ACCESS", user.username(), "ALLOWED",
                "permission=" + requiredPermission + " sessionId=" + record.getSessionId());
        return AccessDecision.allow(user.username(), record.getSessionId());
    }

    private AccessDecision denyForState(AccessRecord record, SessionState state) {
        AccessDeniedReason reason = switch (state) {
            case REVOKED -> AccessDeniedReason.SESSION_REVOKED;
            case IDLE_TIMEOUT -> AccessDeniedReason.SESSION_IDLE;
            case EVICTED -> AccessDeniedReason.SESSION_EVICTED;
            case EXPIRED -> AccessDeniedReason.SESSION_EXPIRED;
            case ACTIVE -> AccessDeniedReason.SESSION_REVOKED;
        };
        return deny(record.getUsername(), reason,
                "session state=" + state + " sessionId=" + record.getSessionId());
    }

    private AccessDeniedReason denyReasonFor(AccessRevokeReason revokeReason) {
        return switch (revokeReason) {
            case SESSION_REVOKED -> AccessDeniedReason.TOKEN_REVOKED;
            case IDLE_TIMEOUT -> AccessDeniedReason.SESSION_IDLE;
            case EVICTED -> AccessDeniedReason.SESSION_EVICTED;
        };
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
