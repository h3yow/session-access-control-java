package com.github.h3yow.sessionaccesscontroljava.web;

import com.github.h3yow.sessionaccesscontroljava.access.RequirePermission;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceOutcome;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceResult;
import com.github.h3yow.sessionaccesscontroljava.governance.SessionGovernanceService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 会话治理端点（均需 session:manage，即任一已认证用户管理"自己名下"的会话）。
 * 用户名/会话 ID 取自认证拦截器写入的请求属性，绝不信任请求体里自称的身份。
 */
@RestController
@RequestMapping("/api/sessions")
@RequirePermission("session:manage")
public class SessionController {

    private final SessionGovernanceService governanceService;

    public SessionController(SessionGovernanceService governanceService) {
        this.governanceService = governanceService;
    }

    /** 列出当前用户所有仍活跃会话（不含任何凭证内容）。 */
    @GetMapping
    public ResponseEntity<GovernanceResult> list(HttpServletRequest request) {
        GovernanceResult result = governanceService.listSessions(
                (String) request.getAttribute("username"),
                (String) request.getAttribute("sessionId"));
        return ResponseEntity.ok(result);
    }

    /** 撤销指定单条会话；越权访问他人会话 -> 403。 */
    @PostMapping("/{sessionId}/revoke")
    public ResponseEntity<GovernanceResult> revokeOne(HttpServletRequest request,
                                                      @PathVariable String sessionId) {
        GovernanceResult result = governanceService.revokeSession(
                (String) request.getAttribute("username"),
                (String) request.getAttribute("sessionId"),
                sessionId);
        return ResponseEntity.status(mapStatus(result.outcome())).body(result);
    }

    /** 撤销除当前会话外的其他活跃会话。 */
    @PostMapping("/revoke-others")
    public ResponseEntity<GovernanceResult> revokeOthers(HttpServletRequest request) {
        GovernanceResult result = governanceService.revokeOtherSessions(
                (String) request.getAttribute("username"),
                (String) request.getAttribute("sessionId"));
        return ResponseEntity.ok(result);
    }

    private HttpStatus mapStatus(GovernanceOutcome outcome) {
        return switch (outcome) {
            case REVOKE_SESSION_SUCCESS, REVOKE_OTHERS_SUCCESS, LIST_SUCCESS -> HttpStatus.OK;
            case SESSION_NOT_OWNED -> HttpStatus.FORBIDDEN;
            case SESSION_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case SESSION_NOT_ACTIVE -> HttpStatus.CONFLICT;
        };
    }
}
