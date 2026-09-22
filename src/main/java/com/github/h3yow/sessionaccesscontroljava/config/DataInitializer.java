package com.github.h3yow.sessionaccesscontroljava.config;

import com.github.h3yow.sessionaccesscontroljava.auth.AppUser;
import com.github.h3yow.sessionaccesscontroljava.auth.PasswordHasher;
import com.github.h3yow.sessionaccesscontroljava.auth.UserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

/**
 * 初始化演示用户：
 * - alice / password123 : ROLE_USER            -> profile:read
 * - admin / admin123    : ROLE_ADMIN           -> profile:read, admin:read
 * - bob / bob123        : ROLE_FINANCE + 细粒度 finance:read
 */
@Configuration
public class DataInitializer {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    @Bean
    CommandLineRunner initUsers(UserDirectory userDirectory, PasswordHasher passwordHasher) {
        return args -> {
            userDirectory.register(new AppUser("alice",
                    passwordHasher.hash("password123"),
                    Set.of("ROLE_USER"), Set.of()));
            userDirectory.register(new AppUser("admin",
                    passwordHasher.hash("admin123"),
                    Set.of("ROLE_ADMIN"), Set.of()));
            userDirectory.register(new AppUser("bob",
                    passwordHasher.hash("bob123"),
                    Set.of("ROLE_FINANCE"), Set.of()));
            log.info("demo-users-initialized [alice/password123, admin/admin123, bob/bob123]");
        };
    }
}
