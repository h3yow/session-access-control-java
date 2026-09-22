package com.github.h3yow.sessionaccesscontroljava.demo;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AuditEvent;
import com.github.h3yow.sessionaccesscontroljava.auth.security.AuditService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 审计查询端点：返回全部审计记录，便于本地核对关键输入与判定依据。
 * 需要 admin:read 权限（仅 ADMIN）。
 */
@RestController
@RequestMapping("/api/demo/audits")
public class AuditController {

    private final AuditService auditService;

    public AuditController(AuditService auditService) {
        this.auditService = auditService;
    }

    @GetMapping
    public List<AuditEvent> list() {
        return auditService.events();
    }
}
