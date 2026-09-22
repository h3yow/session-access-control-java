package com.github.h3yow.sessionaccesscontroljava.token;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * 负责生成高熵不透明随机凭证（256 bit，URL-safe Base64）。
 * 访问凭证与刷新凭证使用同一签发器，但通过存储与前缀语义区分用途。
 */
@Component
public class TokenIssuer {

    private static final int TOKEN_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();

    public String issueToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        RANDOM.nextBytes(bytes);
        return ENCODER.encodeToString(bytes);
    }
}
