package com.github.h3yow.sessionaccesscontroljava.auth.security;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;

/**
 * 凭证生成与哈希工具：
 * - 生成不可猜测的随机不透明凭证（只在签发响应中明文出现一次）
 * - 存储与索引一律使用 SHA-256 哈希，避免明文落盘
 * - 账户密码使用“盐 + SHA-256”
 */
@Component
public class TokenHasher {

    private final SecureRandom secureRandom = new SecureRandom();

    /** 生成 URL 安全的随机不透明凭证（十六进制编码）。 */
    public String generateToken(int bytes) {
        byte[] buf = new byte[bytes];
        secureRandom.nextBytes(buf);
        return HexFormat.of().formatHex(buf);
    }

    public String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] out = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public String generateSalt() {
        return generateToken(16);
    }

    public String hashPassword(String rawPassword, String salt) {
        return sha256(salt + ":" + rawPassword);
    }
}
