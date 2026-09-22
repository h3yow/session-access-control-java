package com.github.h3yow.sessionaccesscontroljava.auth.web;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AuthContext;
import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;
import com.github.h3yow.sessionaccesscontroljava.auth.model.TokenIssued;
import com.github.h3yow.sessionaccesscontroljava.auth.security.Authenticator;
import com.github.h3yow.sessionaccesscontroljava.auth.security.TokenService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

/**
 * 认证端点：登录、刷新、主动撤销（登出）。
 * 不同失败原因映射为可区分的 HTTP 状态与 reason 码。
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final Authenticator authenticator;
    private final TokenService tokenService;

    public AuthController(Authenticator authenticator, TokenService tokenService) {
        this.authenticator = authenticator;
        this.tokenService = tokenService;
    }

    public record LoginRequest(String username, String password) {
    }

    public record RefreshRequest(String refreshToken) {
    }

    public record LogoutRequest(String sessionId) {
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        TokenIssued issued = authenticator.login(request.username(), request.password());
        return toResponse(issued);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
        TokenIssued issued = tokenService.refresh(request.refreshToken());
        return toResponse(issued);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest httpRequest, @RequestBody(required = false) LogoutRequest body) {
        // 能到达这里说明已通过认证并具备基础权限 profile:read（任意已认证用户均可登出自己）
        AuthContext context = (AuthContext) httpRequest.getAttribute(SecurityInterceptor.AUTH_CONTEXT_ATTR);

        String targetSessionId = body != null && body.sessionId() != null && !body.sessionId().isBlank()
                ? body.sessionId()
                : context.sessionId();

        // 普通用户只能撤销自己的会话；撤销他人会话需具备更高权限（此处简单判定）
        boolean self = targetSessionId.equals(context.sessionId());
        boolean canRevokeOthers = context.roles().stream()
                .anyMatch(r -> r.permissions().contains("admin:write"));
        if (!self && !canRevokeOthers) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorResponse(
                    Instant.now(), HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase(),
                    DecisionReason.INSUFFICIENT_PERMISSION,
                    "can only revoke your own session", httpRequest.getRequestURI()));
        }

        boolean revoked = tokenService.revokeSession(targetSessionId, context.username());
        if (!revoked) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorResponse(
                    Instant.now(), HttpStatus.NOT_FOUND.value(), HttpStatus.NOT_FOUND.getReasonPhrase(),
                    DecisionReason.REVOKED, "session not found", httpRequest.getRequestURI()));
        }
        return ResponseEntity.ok(Map.of(
                "success", true,
                "sessionId", targetSessionId,
                "message", "session revoked"));
    }

    private ResponseEntity<?> toResponse(TokenIssued issued) {
        if (issued.success()) {
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "sessionId", issued.sessionId(),
                    "accessToken", issued.accessToken(),
                    "refreshToken", issued.refreshToken(),
                    "accessTokenExpiresAt", issued.accessTokenExpiresAt(),
                    "refreshTokenExpiresAt", issued.refreshTokenExpiresAt()));
        }
        HttpStatus status = switch (issued.reason()) {
            case ACCOUNT_LOCKED -> HttpStatus.TOO_MANY_REQUESTS;
            case REFRESH_TOKEN_REUSED -> HttpStatus.CONFLICT;
            case EXPIRED -> HttpStatus.UNAUTHORIZED;
            default -> HttpStatus.UNAUTHORIZED;
        };
        return ResponseEntity.status(status).body(new ErrorResponse(
                Instant.now(), status.value(), status.getReasonPhrase(),
                issued.reason(), issued.message(), null));
    }
}
