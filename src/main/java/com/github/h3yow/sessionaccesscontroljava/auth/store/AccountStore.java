package com.github.h3yow.sessionaccesscontroljava.auth.store;

import com.github.h3yow.sessionaccesscontroljava.auth.model.Account;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 账户存储（内存实现），由 DataInitializer 预置演示账户。
 */
@Component
public class AccountStore {

    private final ConcurrentMap<String, Account> accounts = new ConcurrentHashMap<>();

    public void put(Account account) {
        accounts.put(account.username(), account);
    }

    public Optional<Account> find(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(accounts.get(username));
    }
}
