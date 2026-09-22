package com.github.h3yow.sessionaccesscontroljava.auth.model;

import java.util.Set;

/**
 * 访问凭证校验通过后得到的认证上下文。
 */
public record AuthContext(
        String username,
        Set<Role> roles,
        String sessionId,
        String accessTokenHash
) {
}
