package com.github.h3yow.sessionaccesscontroljava.governance;

import com.github.h3yow.sessionaccesscontroljava.audit.AuditService;
import com.github.h3yow.sessionaccesscontroljava.clock.TickClock;
import com.github.h3yow.sessionaccesscontroljava.session.AccessRevokeReason;
import com.github.h3yow.sessionaccesscontroljava.session.SessionChain;
import com.github.h3yow.sessionaccesscontroljava.session.SessionRepository;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * 会话治理服务。
 *
 * 隔离与授权语义：
 * - 所有操作都以调用方经过认证的 username 为边界；只可能看到/撤销自己名下会话。
 * - 列表只返回"仍活跃"的会话（先在用户监视器内惰性收敛闲置/过期/淘汰），且条目不含任何凭证。
 * - 定向撤销对三种失败给出可区分结果：
 *   SESSION_NOT_FOUND（ID 不存在）/ SESSION_NOT_OWNED（归属他人，越权明确拒绝）
 *   / SESSION_NOT_ACTIVE（已在终态，终态不可重新激活）。
 *
 * 并发语义：与登录容量淘汰、刷新、访问活动推进共用同一把用户监视器，
 * 因此并发撤销/刷新/淘汰时计数与状态唯一收敛，不会出现两条有效链。
 */
@Service
public class SessionGovernanceService {

    private static final Logger log = LoggerFactory.getLogger(SessionGovernanceService.class);

    private final SessionRepository sessionRepository;
    private final TickClock clock;
    private final AuditService auditService;
    private final Duration idleTtl;

    public SessionGovernanceService(SessionRepository sessionRepository,
                                    TickClock clock,
                                    AuditService auditService,
                                    @org.springframework.beans.factory.annotation.Value("${auth.session.idle-ttl:PT30M}")
                                    Duration idleTtl) {
        this.sessionRepository = sessionRepository;
        this.clock = clock;
        this.auditService = auditService;
        this.idleTtl = idleTtl;
    }

    /** 列出本人名下所有仍活跃的会话（不含凭证），最近活动时间倒序。 */
    public GovernanceResult listSessions(String username, String currentSessionId) {
        log.info("session-list username={} currentSessionId={}", username, currentSessionId);
        List<SessionView> views = new ArrayList<>();
        synchronized (sessionRepository.userLock(username)) {
            List<SessionChain> chains = sessionRepository.chainsOf(username);
            for (SessionChain chain : chains) {
                SessionState state = sessionRepository.settleTimeBasedState(chain, clock.now(), idleTtl);
                if (state != SessionState.ACTIVE) {
                    continue;
                }
                views.add(new SessionView(
                        chain.getSessionId(),
                        chain.getCreatedAt(),
                        chain.getLastActivityAt(),
                        chain.getRefreshTokenExpiresAt(),
                        chain.getSessionId().equals(currentSessionId)));
            }
        }
        views.sort(Comparator.comparing(SessionView::lastActivityAt).reversed());
        auditService.record("SESSION_GOVERNANCE", username, "LIST_SUCCESS",
                "activeSessions=" + views.size());
        return GovernanceResult.list(views);
    }

    /**
     * 撤销指定的一条会话。
     * 越权（会话归属他人）明确拒绝，且不泄漏该会话是否存在。
     */
    public GovernanceResult revokeSession(String username, String currentSessionId, String targetSessionId) {
        log.info("session-revoke-one username={} actorSession={} target={}",
                username, currentSessionId, targetSessionId);
        if (targetSessionId == null || targetSessionId.isBlank()) {
            auditService.record("SESSION_GOVERNANCE", username, "SESSION_NOT_FOUND", "missing target session id");
            return GovernanceResult.failure(GovernanceOutcome.SESSION_NOT_FOUND, "session id is required");
        }

        var chainOpt = sessionRepository.findById(targetSessionId);
        if (chainOpt.isEmpty()) {
            auditService.record("SESSION_GOVERNANCE", username, "SESSION_NOT_FOUND",
                    "target not found sessionId=" + targetSessionId);
            return GovernanceResult.failure(GovernanceOutcome.SESSION_NOT_FOUND, "session not found");
        }
        SessionChain chain = chainOpt.get();
        if (!chain.getUsername().equals(username)) {
            // 越权：明确拒绝。不改变目标会话任何状态。
            log.warn("session-revoke-denied username={} reason=SESSION_NOT_OWNED owner={} target={}",
                    username, chain.getUsername(), targetSessionId);
            auditService.record("SESSION_GOVERNANCE", username, "SESSION_NOT_OWNED",
                    "attempted revoke of another user's session target=" + targetSessionId);
            return GovernanceResult.failure(GovernanceOutcome.SESSION_NOT_OWNED,
                    "you are not allowed to revoke this session");
        }

        synchronized (sessionRepository.userLock(username)) {
            SessionState state = sessionRepository.settleTimeBasedState(chain, clock.now(), idleTtl);
            if (state != SessionState.ACTIVE) {
                auditService.record("SESSION_GOVERNANCE", username, "SESSION_NOT_ACTIVE",
                        "sessionId=" + targetSessionId + " state=" + state);
                return GovernanceResult.failure(GovernanceOutcome.SESSION_NOT_ACTIVE,
                        "session is no longer active (state=" + state + ")");
            }
            sessionRepository.terminate(chain, SessionState.REVOKED, AccessRevokeReason.SESSION_REVOKED);
        }
        log.info("session-revoke-one-success username={} target={} current={}",
                username, targetSessionId, targetSessionId.equals(currentSessionId));
        auditService.record("SESSION_GOVERNANCE", username, "REVOKE_SESSION_SUCCESS",
                "revoked sessionId=" + targetSessionId);
        return GovernanceResult.ok(GovernanceOutcome.REVOKE_SESSION_SUCCESS, 1, "session revoked");
    }

    /** 撤销本人除当前会话外的其他全部活跃会话；返回被撤销条数。 */
    public GovernanceResult revokeOtherSessions(String username, String currentSessionId) {
        log.info("session-revoke-others username={} currentSessionId={}", username, currentSessionId);
        List<SessionChain> targets = new ArrayList<>();
        synchronized (sessionRepository.userLock(username)) {
            for (SessionChain chain : sessionRepository.chainsOf(username)) {
                SessionState state = sessionRepository.settleTimeBasedState(chain, clock.now(), idleTtl);
                if (state == SessionState.ACTIVE && !chain.getSessionId().equals(currentSessionId)) {
                    targets.add(chain);
                }
            }
            for (SessionChain chain : targets) {
                // 当前会话在同一用户临界区内，settle 判定为 ACTIVE 后不可能在本循环期间被淘汰
                sessionRepository.terminate(chain, SessionState.REVOKED, AccessRevokeReason.SESSION_REVOKED);
            }
        }
        log.info("session-revoke-others-success username={} keptCurrent={} revoked={}",
                username, currentSessionId, targets.size());
        auditService.record("SESSION_GOVERNANCE", username, "REVOKE_OTHERS_SUCCESS",
                "revoked=" + targets.size() + " keptCurrent=" + currentSessionId);
        return GovernanceResult.ok(GovernanceOutcome.REVOKE_OTHERS_SUCCESS, targets.size(),
                "other sessions revoked");
    }
}
