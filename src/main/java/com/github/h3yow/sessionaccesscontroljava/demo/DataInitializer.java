package com.github.h3yow.sessionaccesscontroljava.demo;

import com.github.h3yow.sessionaccesscontroljava.auth.model.Account;
import com.github.h3yow.sessionaccesscontroljava.auth.model.Role;
import com.github.h3yow.sessionaccesscontroljava.auth.security.TokenHasher;
import com.github.h3yow.sessionaccesscontroljava.auth.store.AccountStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

/**
 * 预置演示账户（启动时写入内存账户库）：
 * <ul>
 *   <li>alice / password-123 -> ADMIN</li>
 *   <li>bob   / password-123 -> USER</li>
 *   <li>carol / password-123 -> GUEST</li>
 * </ul>
 * 密码以“盐 + SHA-256”存储，不保存明文。
 */
@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final AccountStore accountStore;
    private final TokenHasher tokenHasher;

    public DataInitializer(AccountStore accountStore, TokenHasher tokenHasher) {
        this.accountStore = accountStore;
        this.tokenHasher = tokenHasher;
    }

    @Override
    public void run(String... args) {
        String rawPassword = "password-123";
        List<Seed> seeds = List.of(
                new Seed("alice", Set.of(Role.ADMIN)),
                new Seed("bob", Set.of(Role.USER)),
                new Seed("carol", Set.of(Role.GUEST))
        );
        for (Seed seed : seeds) {
            String salt = tokenHasher.generateSalt();
            String hash = tokenHasher.hashPassword(rawPassword, salt);
            accountStore.put(new Account(seed.username(), salt, hash, seed.roles()));
        }
        log.info("Seeded demo accounts (password='{}'): alice=ADMIN, bob=USER, carol=GUEST", rawPassword);
    }

    private record Seed(String username, Set<Role> roles) {
    }
}
