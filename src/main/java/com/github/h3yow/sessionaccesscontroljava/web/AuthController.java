package com.github.h3yow.sessionaccesscontroljava.web;

import com.github.h3yow.sessionaccesscontroljava.auth.AuthOutcome;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthResult;
import com.github.h3yow.sessionaccesscontroljava.auth.AuthService;
import com.github.h3yow.sessionaccesscontroljava.token.TokenPair;
import com.github.h3yow.sessionaccesscontroljava.web.dto.AuthResponse;
import com.github.h3yow.sessionaccesscontroljava.web.dto.LoginRequest;
import com.github.h3yow.sessionaccesscontroljava.web.dto.RefreshRequest;
import com.github.h3yow.sessionaccesscontroljava.web.dto.RevokeRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 认证端点：/api/auth/login、/refresh、/revoke。 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody LoginRequest request) {
        log.info("http-login username={}", request.username());
        AuthResult result = authService.login(request.username(), request.password());
        return toResponse(result);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody RefreshRequest request) {
        log.info("http-refresh");
        AuthResult result = authService.refresh(request.refreshToken());
        return toResponse(result);
    }

    @PostMapping("/revoke")
    public ResponseEntity<AuthResponse> revoke(@RequestBody RevokeRequest request) {
        log.info("http-revoke");
        AuthResult result = authService.revoke(request.refreshToken());
        return toResponse(result);
    }

    private ResponseEntity<AuthResponse> toResponse(AuthResult result) {
        TokenPair tokens = result.tokens();
        AuthResponse body = new AuthResponse(
                result.isSuccess(),
                result.outcome().name(),
                result.message(),
                tokens == null ? null : tokens.accessToken(),
                tokens == null ? null : tokens.refreshToken(),
                tokens == null ? null : tokens.accessTokenExpiresAt(),
                tokens == null ? null : tokens.refreshTokenExpiresAt());
        return switch (result.outcome()) {
            case LOGIN_SUCCESS, REFRESH_SUCCESS -> ResponseEntity.status(HttpStatus.OK).body(body);
            case REVOKE_SUCCESS -> ResponseEntity.status(HttpStatus.OK).body(body);
            case INVALID_CREDENTIALS -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
            case ACCOUNT_LOCKED -> ResponseEntity.status(HttpStatus.LOCKED).body(body);
            case REFRESH_TOKEN_UNKNOWN -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
            case REFRESH_TOKEN_EXPIRED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
            case SESSION_REVOKED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
            case REFRESH_TOKEN_REUSED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
            case SESSION_IDLE_TIMEOUT, SESSION_EVICTED -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
            case REVOKE_NOT_FOUND -> ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
        };
    }
}
