package com.github.h3yow.sessionaccesscontroljava.auth;

import java.util.Set;

/** 系统内用户主体。 */
public record AppUser(String username, String passwordHash, Set<String> roles, Set<String> permissions) {
}
