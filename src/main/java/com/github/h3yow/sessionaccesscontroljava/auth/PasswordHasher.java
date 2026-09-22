package com.github.h3yow.sessionaccesscontroljava.auth;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * SHA-256 密码摘要（本地演示用途，非生产级口令存储方案）。
 * 使用常量时间比较避免摘要比对侧信道。
 */
@Component
public class PasswordHasher {

    public String hash(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] out = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public boolean matches(String raw, String hash) {
        if (raw == null || hash == null) {
            return false;
        }
        return MessageDigest.isEqual(
                hash.getBytes(StandardCharsets.UTF_8),
                hash(raw).getBytes(StandardCharsets.UTF_8));
    }
}
