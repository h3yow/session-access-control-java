package com.github.h3yow.sessionaccesscontroljava.auth.store;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AuditEvent;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 审计记录存储（内存实现，只追加）。
 *
 * 约定：审计写入失败由 {@code AuditService} 捕获并记录日志，
 * 绝不向认证/授权调用方抛出异常，因此不改变最终判定结果。
 * 这里使用线程安全列表，保证并发请求下记录不丢失、顺序近似全序。
 */
@Component
public class AuditStore {

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();

    public void append(AuditEvent event) {
        events.add(event);
    }

    public List<AuditEvent> list() {
        return List.copyOf(events);
    }
}
