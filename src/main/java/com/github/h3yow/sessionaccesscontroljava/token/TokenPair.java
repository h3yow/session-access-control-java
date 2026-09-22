package com.github.h3yow.sessionaccesscontroljava.token;

import java.time.Instant;

/** 一次签发/刷新产出的凭证对：短期访问凭证 + 长期刷新凭证。 */
public record TokenPair(
        String accessToken,
        String refreshToken,
        Instant accessTokenExpiresAt,
        Instant refreshTokenExpiresAt
) {
}
