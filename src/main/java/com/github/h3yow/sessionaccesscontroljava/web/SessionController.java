package com.github.h3yow.sessionaccesscontroljava.web;

import com.github.h3yow.sessionaccesscontroljava.access.RequirePermission;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceOutcome;
import com.github.h3yow.sessionaccesscontroljava.governance.GovernanceResult;
import com.github.h3yow.sessionaccesscontroljava.governance.SessionGovernanceService;
import com.github.h3yow.sessionaccesscontroljava.session.SessionView;
import com.github.h3yow.sessionaccesscontroljava.web.dto.GovernanceResponse;
import com.github.h3yow.sessionaccesscontroljava.web.dto.SessionInfoResponse;
import com.github.h3yow.sessionaccesscontroljava.web.dto.SessionListResponse;
import com.github.h3yow.sessionaccesscontroljava.web.dto.SessionRevokeRequest;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 会话治理端点（均需登录且具备 session:manage 自身会话权限）：
 * - GET    /api/sessions           列举本人名下存活会话
 * - POST   /api/sessions/revoke    精确撤销一条（按 sessionId）
 * - DELETE /api/sessions/others    撤销除当前外的其它会话
 */
@RestController
@RequestMapping("/api/sessions")
public class SessionController {

    private static final Logger log = LoggerFactory.getLogger(SessionController.class);

    private final SessionGovernanceService governanceService;

    public SessionController(SessionGovernanceService governanceService) {
        this.governanceService = governanceService;
    }

    @GetMapping
    @RequirePermission("session:manage")
    public SessionListResponse list(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        String sessionId = (String) request.getAttribute("sessionId");
        log.info("http-session-list username={} currentSessionId={}", username, sessionId);
        GovernanceResult result = governanceService.listSessions(username, sessionId);
        List<SessionInfoResponse> infos = result.sessions() == null ? List.of()
                : result.sessions().stream().map(this::toInfo).toList();
        return new SessionListResponse(result.isSuccess(), result.outcome().name(),
                result.message(), infos);
    }

    @PostMapping("/revoke")
    @RequirePermission("session:manage")
    public ResponseEntity<GovernanceResponse> revoke(HttpServletRequest request,
                                                     @RequestBody SessionRevokeRequest body) {
        String username = (String) request.getAttribute("username");
        String currentSessionId = (String) request.getAttribute("sessionId");
        String target = body == null ? null : body.sessionId();
        log.info("http-session-revoke username={} currentSessionId={} targetSessionId={}",
                username, currentSessionId, target);
        GovernanceResult result = governanceService.revokeSession(username, currentSessionId, target);
        return toResponse(result);
    }

    @DeleteMapping("/others")
    @RequirePermission("session:manage")
    public ResponseEntity<GovernanceResponse> revokeOthers(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        String currentSessionId = (String) request.getAttribute("sessionId");
        log.info("http-session-revoke-others username={} currentSessionId={}", username, currentSessionId);
        GovernanceResult result = governanceService.revokeOtherSessions(username, currentSessionId);
        return toResponse(result);
    }

    private SessionInfoResponse toInfo(SessionView view) {
        return new SessionInfoResponse(view.sessionId(), view.createdAt(),
                view.lastActivityAt(), view.current());
    }

    private ResponseEntity<GovernanceResponse> toResponse(GovernanceResult result) {
        GovernanceResponse body = new GovernanceResponse(
                result.isSuccess(), result.outcome().name(), result.message(), result.revokedCount());
        HttpStatus status = switch (result.outcome()) {
            case SESSION_REVOKED, SESSIONS_REVOKED_OTHERS -> HttpStatus.OK;
            case SESSION_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case SESSION_FORBIDDEN -> HttpStatus.FORBIDDEN;
            case SESSIONS_LISTED -> HttpStatus.OK;
        };
        return ResponseEntity.status(status).body(body);
    }
}
