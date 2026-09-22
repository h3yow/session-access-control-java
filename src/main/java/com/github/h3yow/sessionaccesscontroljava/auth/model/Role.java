package com.github.h3yow.sessionaccesscontroljava.auth.model;

import java.util.Set;

/**
 * 角色及其拥有的权限。授权基于权限字符串判定，默认拒绝。
 */
public enum Role {

    ADMIN(Set.of("profile:read", "admin:read", "admin:write")),
    USER(Set.of("profile:read")),
    GUEST(Set.of());

    private final Set<String> permissions;

    Role(Set<String> permissions) {
        this.permissions = permissions;
    }

    public Set<String> permissions() {
        return permissions;
    }
}
