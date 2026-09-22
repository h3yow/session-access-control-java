package com.github.h3yow.sessionaccesscontroljava.web.dto;

import java.time.Instant;

public record AuthResponse(
        boolean success,
        String reason,
        String message,
        String accessToken,
        String refreshToken,
        Instant accessTokenExpiresAt,
        Instant refreshTokenExpiresAt
) {
}
