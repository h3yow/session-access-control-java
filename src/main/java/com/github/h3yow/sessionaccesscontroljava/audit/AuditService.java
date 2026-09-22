package com.github.h3yow.sessionaccesscontroljava.audit;

import com.github.h3yow.sessionaccesscontroljava.clock.TickClock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 审计服务：记录每一次认证/授权判定，同时输出结构化日志并保留内存副本（便于测试断言）。
 *
 * 关键语义：审计写入被 try/catch 完全包裹，任何写入失败只产生内部告警，
 * 绝不向上抛出、绝不改变认证与授权的最终判定结果。
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final TickClock clock;
    private final List<AuditEvent> events = Collections.synchronizedList(new ArrayList<>());

    public AuditService(TickClock clock) {
        this.clock = clock;
    }

    public void record(String action, String subject, String result, String detail) {
        try {
            AuditEvent event = new AuditEvent(clock.now(), action, subject, result, detail);
            events.add(event);
            log.info("audit|action={}|subject={}|result={}|detail={}", action, subject, result, detail);
        } catch (Exception e) {
            // 审计失败不得影响主判定流程
            log.error("audit-write-failed action={} subject={} result={} err={}",
                    action, subject, result, e.toString());
        }
    }

    /** 只读审计快照（测试/排障用）。 */
    public List<AuditEvent> snapshot() {
        synchronized (events) {
            return List.copyOf(events);
        }
    }
}
