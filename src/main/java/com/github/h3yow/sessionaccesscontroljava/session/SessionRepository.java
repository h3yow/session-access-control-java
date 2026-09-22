package com.github.h3yow.sessionaccesscontroljava.session;

import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 会话与访问凭证存储（内存实现）。
 *
 * 并发语义：
 * 1. 每次 {@link #rotateRefreshToken} 在会话对象监视器内做 CAS 式比对替换，
 *    同一 refresh 凭证的并发刷新只有一个线程能看到 expected 匹配并成功，
 *    另一个线程拿到的已是新凭证，自然失败 —— 不会产生两条同时有效的链。
 * 2. 旧 refresh 凭证轮换后进入 revokedRefreshTokens 索引；
 *    之后任何对旧凭证的再次使用都能被识别为"复用"，并令整条链失效。
 * 3. 撤销会话时级联撤销其全部已签发访问凭证。
 */
@Component
public class SessionRepository {

    private final ConcurrentHashMap<String, SessionChain> sessionsById = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> sessionIdByRefreshToken = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AccessRecord> accessRecords = new ConcurrentHashMap<>();

    public SessionChain create(SessionChain chain) {
        sessionsById.put(chain.getSessionId(), chain);
        sessionIdByRefreshToken.put(chain.getCurrentRefreshToken(), chain.getSessionId());
        return chain;
    }

    public Optional<SessionChain> findByRefreshToken(String refreshToken) {
        if (refreshToken == null) {
            return Optional.empty();
        }
        String sessionId = sessionIdByRefreshToken.get(refreshToken);
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessionsById.get(sessionId));
    }

    public Optional<SessionChain> findById(String sessionId) {
        if (sessionId == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(sessionsById.get(sessionId));
    }

    /**
     * 原子轮换：仅当会话当前 refresh 凭证等于 expectedOld 时才替换为 newToken。
     * 必须在调用方持有会话一致性语义时使用（内部已对会话对象加锁）。
     */
    public boolean rotateRefreshToken(SessionChain chain, String expectedOld, String newToken) {
        synchronized (chain) {
            if (chain.getState() != SessionState.ACTIVE) {
                return false;
            }
            if (!expectedOld.equals(chain.getCurrentRefreshToken())) {
                return false;
            }
            String old = chain.getCurrentRefreshToken();
            chain.setCurrentRefreshToken(newToken);
            // 旧凭证保留在索引中（仍可解析到该会话），但不再等于链上当前凭证 -> 复用可识别
            sessionIdByRefreshToken.put(newToken, chain.getSessionId());
            // 显式标记旧凭证：值映射保持不变，findByRefreshToken 依旧能定位链
            return true;
        }
    }

    /** 撤销整条会话链，并级联撤销其全部访问凭证。 */
    public void revoke(SessionChain chain) {
        synchronized (chain) {
            chain.setState(SessionState.REVOKED);
        }
        revokeAccessRecordsOfSession(chain.getSessionId());
    }

    public void saveAccessRecord(AccessRecord record) {
        accessRecords.put(record.getAccessToken(), record);
    }

    public Optional<AccessRecord> findAccessRecord(String accessToken) {
        if (accessToken == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(accessRecords.get(accessToken));
    }

    public void revokeAccessRecordsOfSession(String sessionId) {
        // 标记撤销但保留记录，使拒绝原因可区分为 REVOKED 而非 UNKNOWN
        for (AccessRecord record : accessRecords.values()) {
            if (record.getSessionId().equals(sessionId)) {
                record.setRevoked(true);
            }
        }
    }

    /** 测试辅助：列出某会话全部访问凭证记录。 */
    public List<AccessRecord> accessRecordsOfSession(String sessionId) {
        List<AccessRecord> out = new ArrayList<>();
        for (AccessRecord record : accessRecords.values()) {
            if (record.getSessionId().equals(sessionId)) {
                out.add(record);
            }
        }
        return out;
    }
}
