package com.github.h3yow.sessionaccesscontroljava.auth;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** 用户目录（本地演示用内存实现，启动时由 DataInitializer 填充演示用户）。 */
@Component
public class UserDirectory {

    private final ConcurrentHashMap<String, AppUser> users = new ConcurrentHashMap<>();

    public Optional<AppUser> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(users.get(username));
    }

    public void register(AppUser user) {
        users.put(user.username(), user);
    }
}
