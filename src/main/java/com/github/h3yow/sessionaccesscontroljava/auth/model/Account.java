package com.github.h3yow.sessionaccesscontroljava.auth.model;

import java.util.Set;

/**
 * 本地账户。密码以“盐 + 哈希”形式存储，不保存明文。
 */
public record Account(
        String username,
        String passwordSalt,
        String passwordHash,
        Set<Role> roles
) {
}
