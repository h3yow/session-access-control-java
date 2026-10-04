package com.github.h3yow.sessionaccesscontroljava.governance;

import com.github.h3yow.sessionaccesscontroljava.audit.AuditService;
import com.github.h3yow.sessionaccesscontroljava.clock.TickClock;
import com.github.h3yow.sessionaccesscontroljava.session.SessionChain;
import com.github.h3yow.sessionaccesscontroljava.session.SessionRepository;
import com.github.h3yow.sessionaccesscontroljava.session.SessionState;
import com.github.h3yow.sessionaccesscontroljava.session.SessionView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * 会话治理服务：列举名下存活会话、精确撤销单条、撤销除当前外的其它会话。
 *
 * 安全与并发语义（实现见各方法）：
 * - 所有操作都以"当前访问凭证解析出的用户"为归属边界，跨用户查看/撤销一律 FORBIDDEN。
 * - 列表视图不含任何凭证内容。
 * - 撤销即时生效（会话进入 REVOKED 终态并级联撤销其访问凭证），终态不可被重新激活。
 */
@Service
public class SessionGovernanceService {

    private static final Logger log = LoggerFactory.getLogger(SessionGovernanceService.class);

    private final SessionRepository sessionRepository;
    private final TickClock clock;
    private final AuditService auditService;
    private final Duration idleTimeout;
    private final int maxSessionsPerUser;

    public SessionGovernanceService(SessionRepository sessionRepository,
                                    TickClock clock,
                                    AuditService auditService,
                                    @Value("${auth.session.idle-timeout:PT30M}") Duration idleTimeout,
                                    @Value("${auth.session.max-per-user:5}") int maxSessionsPerUser) {
        this.sessionRepository = sessionRepository;
        this.clock = clock;
        this.auditService = auditService;
        this.idleTimeout = idleTimeout;
        this.maxSessionsPerUser = maxSessionsPerUser;
    }

    /** 列举当前用户名下所有仍存活（ACTIVE）的会话；按调用者用户边界过滤，绝不返回他人会话。 */
    public GovernanceResult listSessions(String callerUsername, String currentSessionId) {
        log.info("session-list-attempt username={} currentSessionId={}", callerUsername, currentSessionId);
        if (callerUsername == null || callerUsername.isBlank()) {
            return GovernanceResult.failure(GovernanceOutcome.SESSION_FORBIDDEN, "no authenticated caller");
        }
        List<SessionView> views = new ArrayList<>();
        synchronized (sessionRepository.userLock(callerUsername)) {
            // 列表前先做生命周期收敛（绝对过期 + 闲置），保证返回的"存活"集合
            // 与同一时刻的访问、刷新判定遵循同一条规则，绝不展示已绝对过期的会话。
            sessionRepository.transitionTimedOutSessions(callerUsername, clock.now(), idleTimeout);
            List<SessionChain> chains = sessionRepository.sessionsOfUser(callerUsername).stream()
                    .filter(c -> c.getState() == SessionState.ACTIVE)
                    .sorted(Comparator.comparing(SessionChain::getCreatedAt)
                            .thenComparing(SessionChain::getSessionId))
                    .toList();
            for (SessionChain chain : chains) {
                views.add(new SessionView(
                        chain.getSessionId(),
                        chain.getUsername(),
                        chain.getCreatedAt(),
                        chain.getLastActivityAt(),
                        chain.getSessionId().equals(currentSessionId),
                        chain.getState()));
            }
        }
        log.info("session-list-success username={} activeCount={}", callerUsername, views.size());
        auditService.record("SESSION", callerUsername, "SESSIONS_LISTED",
                "active sessions count=" + views.size());
        return GovernanceResult.listed(views);
    }

    /** 精确撤销一条会话：仅属主可撤销；他人会话 -> SESSION_FORBIDDEN；不存在 -> SESSION_NOT_FOUND。 */
    public GovernanceResult revokeSession(String callerUsername, String currentSessionId, String targetSessionId) {
        log.info("session-revoke-attempt username={} currentSessionId={} targetSessionId={}",
                callerUsername, currentSessionId, targetSessionId);
        if (callerUsername == null || callerUsername.isBlank()) {
            return GovernanceResult.failure(GovernanceOutcome.SESSION_FORBIDDEN, "no authenticated caller");
        }
        if (targetSessionId == null || targetSessionId.isBlank()) {
            return GovernanceResult.failure(GovernanceOutcome.SESSION_NOT_FOUND, "sessionId is required");
        }
        Optional<SessionChain> targetOpt = sessionRepository.findById(targetSessionId);
        if (targetOpt.isEmpty()) {
            auditService.record("SESSION", callerUsername, "SESSION_NOT_FOUND",
                    "target sessionId=" + targetSessionId);
            return GovernanceResult.failure(GovernanceOutcome.SESSION_NOT_FOUND, "session not found");
        }
        SessionChain target = targetOpt.get();

        // 归属校验：绝不允许跨用户撤销（即使会话已是终态，也先拒绝越权）
        if (!target.getUsername().equals(callerUsername)) {
            log.warn("session-revoke-forbidden caller={} owner={} targetSessionId={}",
                    callerUsername, target.getUsername(), targetSessionId);
            auditService.record("SESSION", callerUsername, "SESSION_FORBIDDEN",
                    "attempt to revoke another user's session sessionId=" + targetSessionId
                            + " owner=" + target.getUsername());
            return GovernanceResult.failure(GovernanceOutcome.SESSION_FORBIDDEN,
                    "you are not allowed to revoke this session");
        }

        synchronized (sessionRepository.userLock(callerUsername)) {
            SessionState before = target.getState();
            if (before == SessionState.ACTIVE) {
                // revoke 级联撤销该会话全部访问凭证，即时生效
                sessionRepository.revoke(target);
                log.info("session-revoke-success username={} targetSessionId={} currentSessionId={}",
                        callerUsername, targetSessionId, currentSessionId);
                auditService.record("SESSION", callerUsername, "SESSION_REVOKED",
                        "sessionId=" + targetSessionId
                                + (targetSessionId.equals(currentSessionId) ? " (current)" : ""));
                return GovernanceResult.revoked("session revoked");
            }
            // 已在终态：幂等成功，但消息说明既有终态，终态不可被重新激活
            log.info("session-revoke-already-terminal username={} targetSessionId={} state={}",
                    callerUsername, targetSessionId, before);
            auditService.record("SESSION", callerUsername, "SESSION_REVOKED",
                    "already terminal state=" + before + " sessionId=" + targetSessionId);
            return GovernanceResult.revoked("session was already terminal: " + before);
        }
    }

    /** 撤销当前用户名下除当前会话外的全部存活会话。 */
    public GovernanceResult revokeOtherSessions(String callerUsername, String currentSessionId) {
        log.info("session-revoke-others-attempt username={} currentSessionId={}", callerUsername, currentSessionId);
        if (callerUsername == null || callerUsername.isBlank()) {
            return GovernanceResult.failure(GovernanceOutcome.SESSION_FORBIDDEN, "no authenticated caller");
        }
        int count = 0;
        List<String> revokedIds = new ArrayList<>();
        synchronized (sessionRepository.userLock(callerUsername)) {
            sessionRepository.transitionTimedOutSessions(callerUsername, clock.now(), idleTimeout);
            for (SessionChain chain : sessionRepository.sessionsOfUser(callerUsername)) {
                if (chain.getSessionId().equals(currentSessionId)) {
                    continue; // 绝不误伤当前正在使用的会话
                }
                if (chain.getState() == SessionState.ACTIVE) {
                    sessionRepository.revoke(chain);
                    revokedIds.add(chain.getSessionId());
                    count++;
                }
            }
        }
        log.info("session-revoke-others-success username={} currentSessionId={} revokedCount={} ids={}",
                callerUsername, currentSessionId, count, revokedIds);
        auditService.record("SESSION", callerUsername, "SESSIONS_REVOKED_OTHERS",
                "revokedCount=" + count + " kept currentSessionId=" + currentSessionId);
        return GovernanceResult.revokedOthers(count);
    }
}
