package com.github.h3yow.sessionaccesscontroljava.auth.security;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AuditEvent;
import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;
import com.github.h3yow.sessionaccesscontroljava.auth.store.AuditStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

/**
 * 审计服务：记录每次认证/授权判定的关键输入与依据，保证可追溯、可解释。
 *
 * 铁律：审计写入失败只记录错误日志，绝不向调用方抛出异常，
 * 因此审计故障不会改变（更不会“放行”）最终判定结果。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final AuditStore auditStore;
    private final Clock clock;

    public AuditService(AuditStore auditStore, Clock clock) {
        this.auditStore = auditStore;
        this.clock = clock;
    }

    /**
     * 记录一条审计事件。
     *
     * @param action    动作（如 LOGIN / ACCESS / REFRESH / REVOKE / LOGOUT）
     * @param username  相关用户名（未知时可为 null）
     * @param sessionId 相关会话（可为 null）
     * @param outcome   结果（SUCCESS / DENIED / FAILURE）
     * @param reason    可区分的判定原因
     * @param detail    关键输入与判定依据的可读描述
     */
    public void record(String action, String username, String sessionId,
                       String outcome, DecisionReason reason, String detail) {
        try {
            AuditEvent event = new AuditEvent(
                    clock.instant(), action, username, sessionId, outcome, reason, detail);
            auditStore.append(event);
            log.info("AUDIT action={} user={} session={} outcome={} reason={} detail={}",
                    action, username, sessionId, outcome, reason, detail);
        } catch (Exception e) {
            // 审计失败仅记录日志，不影响业务判定
            log.error("AUDIT_WRITE_FAILED action={} user={} reason={} err={}",
                    action, username, reason, e.getMessage(), e);
        }
    }

    public List<AuditEvent> events() {
        return auditStore.list();
    }

    Instant now() {
        return clock.instant();
    }
}
