package com.github.h3yow.sessionaccesscontroljava.auth.security;

import com.github.h3yow.sessionaccesscontroljava.auth.model.AccessTokenEntry;
import com.github.h3yow.sessionaccesscontroljava.auth.model.AuthContext;
import com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason;
import com.github.h3yow.sessionaccesscontroljava.auth.model.RefreshTokenEntry;
import com.github.h3yow.sessionaccesscontroljava.auth.model.Role;
import com.github.h3yow.sessionaccesscontroljava.auth.model.SessionChain;
import com.github.h3yow.sessionaccesscontroljava.auth.model.TokenIssued;
import com.github.h3yow.sessionaccesscontroljava.auth.store.AccessTokenStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.RefreshTokenStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.SessionStore;
import com.github.h3yow.sessionaccesscontroljava.config.SecurityProperties;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 凭证生命周期服务：签发、校验、刷新（轮换 + 重放检测）、撤销。
 *
 * 并发模型（锁顺序固定为“凭证锁 → 会话链锁”，避免死锁）：
 * 1) 同一刷新凭证的并发刷新在 refreshTokenStore 的凭证锁内串行；
 * 2) 链上状态（轮换/撤销）在 sessionStore 的链锁内变更；
 * 3) 因此同一凭证并发刷新至多一次成功，绝不会产生两条同时有效的链。
 *
 * 重放检测：旧刷新凭证轮换后保留为 REPLACED 索引。再次使用即判定
 * {@link DecisionReason#REFRESH_TOKEN_REUSED}，并使整条会话链失效。
 */
@Service
public class TokenService {

    private final SessionStore sessionStore;
    private final RefreshTokenStore refreshTokenStore;
    private final AccessTokenStore accessTokenStore;
    private final TokenHasher tokenHasher;
    private final AuditService auditService;
    private final SecurityProperties properties;
    private final Clock clock;

    public TokenService(SessionStore sessionStore,
                        RefreshTokenStore refreshTokenStore,
                        AccessTokenStore accessTokenStore,
                        TokenHasher tokenHasher,
                        AuditService auditService,
                        SecurityProperties properties,
                        Clock clock) {
        this.sessionStore = sessionStore;
        this.refreshTokenStore = refreshTokenStore;
        this.accessTokenStore = accessTokenStore;
        this.tokenHasher = tokenHasher;
        this.auditService = auditService;
        this.properties = properties;
        this.clock = clock;
    }

    /** 登录成功后创建会话链并签发首组凭证。 */
    public TokenIssued issueForLogin(String username, Set<Role> roles) {
        Instant now = now();
        String sessionId = UUID.randomUUID().toString();
        SessionChain chain = new SessionChain(sessionId, username, roles, now);
        sessionStore.put(chain);

        return sessionStore.withSessionLock(sessionId, () -> {
            TokenPair pair = generatePair();
            Instant accessExp = now.plusSeconds(properties.getAccessTokenTtlSeconds());
            Instant refreshExp = now.plusSeconds(properties.getRefreshTokenTtlSeconds());

            chain.initTokens(pair.accessHash(), accessExp, pair.refreshHash(), refreshExp);
            accessTokenStore.put(new AccessTokenEntry(pair.accessHash(), sessionId, accessExp));
            refreshTokenStore.put(new RefreshTokenEntry(pair.refreshHash(), sessionId, now, refreshExp));

            auditService.record("ISSUE", username, sessionId, "SUCCESS", DecisionReason.ALLOWED,
                    "login issued tokens rotation=" + chain.getRotationVersion());
            return new TokenIssued(true, DecisionReason.ALLOWED, "issued", sessionId,
                    pair.accessRaw(), pair.refreshRaw(), accessExp, refreshExp);
        });
    }

    /**
     * 校验短期访问凭证。
     *
     * @param reasonOut 输出可区分原因：UNAUTHENTICATED / EXPIRED / REVOKED
     * @return 校验通过返回认证上下文，否则 null
     */
    public AuthContext authenticateAccessToken(String accessToken, AtomicReference<DecisionReason> reasonOut) {
        Instant now = now();
        if (accessToken == null || accessToken.isBlank()) {
            reasonOut.set(DecisionReason.UNAUTHENTICATED);
            return null;
        }
        String hash = tokenHasher.sha256(accessToken);
        AccessTokenEntry entry = accessTokenStore.find(hash).orElse(null);
        if (entry == null) {
            reasonOut.set(DecisionReason.UNAUTHENTICATED);
            return null;
        }
        SessionChain chain = sessionStore.find(entry.getSessionId()).orElse(null);
        if (chain == null || chain.isRevoked()) {
            reasonOut.set(DecisionReason.REVOKED);
            return null;
        }
        if (entry.getStatus() == AccessTokenEntry.Status.REVOKED) {
            reasonOut.set(DecisionReason.REVOKED);
            return null;
        }
        if (entry.isExpired(now)) {
            reasonOut.set(DecisionReason.EXPIRED);
            return null;
        }
        // 已被刷新轮换掉的旧访问凭证不再是链上当前凭证，按未认证处理
        if (entry.getStatus() == AccessTokenEntry.Status.REPLACED
                || !hash.equals(chain.getCurrentAccessTokenHash())) {
            reasonOut.set(DecisionReason.UNAUTHENTICATED);
            return null;
        }
        reasonOut.set(DecisionReason.ALLOWED);
        return new AuthContext(chain.getUsername(), chain.getRoles(), chain.getSessionId(), hash);
    }

    /**
     * 刷新：
     * - 凭证不存在/为空 -> TOKEN_UNKNOWN
     * - 凭证已被轮换后再次出现 -> REFRESH_TOKEN_REUSED，整条链撤销
     * - 凭证随链撤销 -> REVOKED
     * - 凭证过期 -> EXPIRED（不撤销链，不签发）
     * - 链已撤销 -> 以链的撤销原因返回（重放场景即 REFRESH_TOKEN_REUSED）
     */
    public TokenIssued refresh(String rawRefreshToken) {
        if (rawRefreshToken == null || rawRefreshToken.isBlank()) {
            auditService.record("REFRESH", null, null, "DENIED",
                    DecisionReason.TOKEN_UNKNOWN, "empty refresh token");
            return TokenIssued.fail(DecisionReason.TOKEN_UNKNOWN, "refresh token is required");
        }
        String hash = tokenHasher.sha256(rawRefreshToken);

        // 第一层：同一刷新凭证串行化，杜绝并发刷新产生两条有效链
        return refreshTokenStore.withTokenLock(hash, () -> {
            RefreshTokenEntry entry = refreshTokenStore.find(hash).orElse(null);
            if (entry == null) {
                auditService.record("REFRESH", null, null, "DENIED",
                        DecisionReason.TOKEN_UNKNOWN, "refresh token not found");
                return TokenIssued.fail(DecisionReason.TOKEN_UNKNOWN, "unknown refresh token");
            }

            // 重放：已轮换凭证再次出现 -> 整链失效（幂等，只处理一次）
            if (entry.getStatus() == RefreshTokenEntry.Status.REPLACED) {
                return handleReplay(entry);
            }
            if (entry.getStatus() == RefreshTokenEntry.Status.REVOKED) {
                auditService.record("REFRESH", null, entry.getSessionId(), "DENIED",
                        DecisionReason.REVOKED, "refresh token revoked at index");
                return TokenIssued.fail(DecisionReason.REVOKED, "refresh token has been revoked");
            }

            // 第二层：链锁内完成“校验 + 轮换”，链状态一致
            return sessionStore.withSessionLock(entry.getSessionId(), () -> rotate(entry, hash));
        });
    }

    private TokenIssued rotate(RefreshTokenEntry entry, String oldHash) {
        Instant now = now();
        SessionChain chain = sessionStore.find(entry.getSessionId()).orElse(null);
        if (chain == null) {
            entry.markRevoked();
            auditService.record("REFRESH", null, entry.getSessionId(), "DENIED",
                    DecisionReason.REVOKED, "session chain missing");
            return TokenIssued.fail(DecisionReason.REVOKED, "session no longer exists");
        }
        if (chain.isRevoked()) {
            // 链可能已因重放/主动撤销失效，返回首次撤销原因（可区分）
            DecisionReason reason = chain.getRevokeReason() != null
                    ? chain.getRevokeReason() : DecisionReason.REVOKED;
            auditService.record("REFRESH", chain.getUsername(), chain.getSessionId(), "DENIED",
                    reason, "session already revoked");
            return TokenIssued.fail(reason, "session has been revoked");
        }
        if (entry.isExpired(now)) {
            auditService.record("REFRESH", chain.getUsername(), chain.getSessionId(), "DENIED",
                    DecisionReason.EXPIRED, "refresh token expired at " + entry.getExpiresAt());
            return TokenIssued.fail(DecisionReason.EXPIRED, "refresh token expired");
        }
        // 双重确认：必须是链上当前凭证，防止索引与链不一致时被利用
        if (!oldHash.equals(chain.getCurrentRefreshTokenHash())) {
            return handleReplay(entry);
        }

        // 记录轮换前的访问凭证，轮换成功后将其标记为 REPLACED
        String previousAccessHash = chain.getCurrentAccessTokenHash();

        TokenPair pair = generatePair();
        Instant accessExp = now.plusSeconds(properties.getAccessTokenTtlSeconds());
        Instant refreshExp = now.plusSeconds(properties.getRefreshTokenTtlSeconds());

        // 先落新凭证索引，再切换链状态，最后旧凭证标记 REPLACED（均在链锁内）
        accessTokenStore.put(new AccessTokenEntry(pair.accessHash(), chain.getSessionId(), accessExp));
        refreshTokenStore.put(new RefreshTokenEntry(pair.refreshHash(), chain.getSessionId(), now, refreshExp));
        boolean rotated = chain.rotate(pair.accessHash(), accessExp, pair.refreshHash(), refreshExp);
        if (!rotated) {
            // 理论上前面已判 revoked，这里防御性处理
            DecisionReason reason = chain.getRevokeReason() != null
                    ? chain.getRevokeReason() : DecisionReason.REVOKED;
            return TokenIssued.fail(reason, "session revoked during rotation");
        }
        entry.markReplaced(pair.refreshHash(), now);
        if (previousAccessHash != null) {
            accessTokenStore.find(previousAccessHash).ifPresent(AccessTokenEntry::markReplaced);
        }

        auditService.record("REFRESH", chain.getUsername(), chain.getSessionId(), "SUCCESS",
                DecisionReason.ALLOWED, "rotated to version " + chain.getRotationVersion());
        return new TokenIssued(true, DecisionReason.ALLOWED, "rotated", chain.getSessionId(),
                pair.accessRaw(), pair.refreshRaw(), accessExp, refreshExp);
    }

    /** 重放处理：撤销整条链（终态幂等），返回可区分原因。 */
    private TokenIssued handleReplay(RefreshTokenEntry entry) {
        SessionChain chain = sessionStore.find(entry.getSessionId()).orElse(null);
        String username = chain != null ? chain.getUsername() : null;
        sessionStore.revoke(entry.getSessionId(), DecisionReason.REFRESH_TOKEN_REUSED, now());
        // 同时撤销当前刷新凭证索引，进一步防止链上当前凭证继续使用
        if (chain != null && chain.getCurrentRefreshTokenHash() != null) {
            refreshTokenStore.find(chain.getCurrentRefreshTokenHash())
                    .ifPresent(RefreshTokenEntry::markRevoked);
        }
        auditService.record("REFRESH_REPLAY", username, entry.getSessionId(), "DENIED",
                DecisionReason.REFRESH_TOKEN_REUSED,
                "reused rotated refresh token issuedAt=" + entry.getIssuedAt()
                        + " replacedAt=" + entry.getReplacedAt() + " -> whole chain invalidated");
        return TokenIssued.fail(DecisionReason.REFRESH_TOKEN_REUSED,
                "refresh token reuse detected; session chain has been invalidated");
    }

    /** 主动撤销会话（登出 / 管理员撤销）。 */
    public boolean revokeSession(String sessionId, String actor) {
        Instant now = now();
        SessionChain chain = sessionStore.find(sessionId).orElse(null);
        if (chain == null) {
            auditService.record("REVOKE", actor, sessionId, "DENIED",
                    DecisionReason.REVOKED, "session not found");
            return false;
        }
        sessionStore.withSessionLock(sessionId, () -> {
            chain.revoke(DecisionReason.REVOKED, now);
            if (chain.getCurrentRefreshTokenHash() != null) {
                refreshTokenStore.find(chain.getCurrentRefreshTokenHash())
                        .ifPresent(RefreshTokenEntry::markRevoked);
            }
            if (chain.getCurrentAccessTokenHash() != null) {
                accessTokenStore.find(chain.getCurrentAccessTokenHash())
                        .ifPresent(AccessTokenEntry::markRevoked);
            }
            return null;
        });
        auditService.record("REVOKE", actor, sessionId, "SUCCESS",
                DecisionReason.REVOKED, "session actively revoked by " + actor);
        return true;
    }

    private TokenPair generatePair() {
        String accessRaw = tokenHasher.generateToken(properties.getTokenBytes());
        String refreshRaw = tokenHasher.generateToken(properties.getTokenBytes());
        return new TokenPair(accessRaw, tokenHasher.sha256(accessRaw),
                refreshRaw, tokenHasher.sha256(refreshRaw));
    }

    Instant now() {
        return clock.instant();
    }

    private record TokenPair(String accessRaw, String accessHash, String refreshRaw, String refreshHash) {
    }
}
