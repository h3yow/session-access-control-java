package com.github.h3yow.sessionaccesscontroljava.auth.store;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AccessTokenEntry;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 访问凭证哈希索引（内存实现）。
 * 凭证状态的变更总是随会话链在链锁内完成；校验路径只做只读查询。
 */
@Component
public class AccessTokenStore {

    private final ConcurrentMap<String, AccessTokenEntry> tokens = new ConcurrentHashMap<>();

    public void put(AccessTokenEntry entry) {
        tokens.put(entry.getTokenHash(), entry);
    }

    public Optional<AccessTokenEntry> find(String tokenHash) {
        if (tokenHash == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(tokens.get(tokenHash));
    }
}
