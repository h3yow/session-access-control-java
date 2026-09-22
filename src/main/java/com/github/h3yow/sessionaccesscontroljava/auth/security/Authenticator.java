package com.github.h3yow.sessionaccesscontroljava.auth.security;

import com.github.h3yow.sessionaccesscontroljava.auth.model.Account;
import com.github.h3yow.sessionaccesscontroljava.auth.model.TokenIssued;
import com.github.h3yow.sessionaccesscontroljava.auth.store.LoginFailureStore;
import com.github.h3yow.sessionaccesscontroljava.auth.store.AccountStore;
import com.github.h3yow.sessionaccesscontroljava.config.SecurityProperties;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;

/**
 * 登录认证：校验账号密码、抑制连续失败登录、成功后签发首组凭证。
 *
 * 一致性语义：
 * - 同一用户名的失败计数与锁定状态更新在用户锁内串行，并发失败不丢计数；
 * - 先判锁定，再校验密码，保证锁定窗口内任何请求都不会“撞开”登录；
 * - 无论成功失败都写审计，且审计失败不影响结果。
 *
 * 说明：对不存在的用户名统一返回 BAD_CREDENTIALS，不额外创建计数，
 * 既避免成为用户枚举/计数放大的入口，也保证真实用户的失败抑制不受干扰。
 */
@Service
public class Authenticator {

    private final AccountStore accountStore;
    private final LoginFailureStore loginFailureStore;
    private final TokenService tokenService;
    private final AuditService auditService;
    private final TokenHasher tokenHasher;
    private final SecurityProperties properties;
    private final Clock clock;

    public Authenticator(AccountStore accountStore,
                         LoginFailureStore loginFailureStore,
                         TokenService tokenService,
                         AuditService auditService,
                         TokenHasher tokenHasher,
                         SecurityProperties properties,
                         Clock clock) {
        this.accountStore = accountStore;
        this.loginFailureStore = loginFailureStore;
        this.tokenService = tokenService;
        this.auditService = auditService;
        this.tokenHasher = tokenHasher;
        this.properties = properties;
        this.clock = clock;
    }

    public TokenIssued login(String username, String rawPassword) {
        Instant now = now();

        if (username == null || username.isBlank() || rawPassword == null) {
            auditService.record("LOGIN", username, null, "DENIED",
                    com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason.BAD_CREDENTIALS,
                    "missing username or password");
            return TokenIssued.fail(
                    com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason.BAD_CREDENTIALS,
                    "invalid credentials");
        }

        // 同一用户串行：读取计数 -> 判定锁定 -> 校验 -> 更新计数，全部原子完成
        return loginFailureStore.withUserLock(username, () -> {
            LoginFailureStore.FailureState state = loginFailureStore.effectiveState(username, now);

            if (state.isLocked(now)) {
                auditService.record("LOGIN", username, null, "DENIED",
                        com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason.ACCOUNT_LOCKED,
                        "account locked until " + state.lockedUntil()
                                + " failures=" + state.failureCount());
                return TokenIssued.fail(
                        com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason.ACCOUNT_LOCKED,
                        "account temporarily locked due to repeated failures");
            }

            Account account = accountStore.find(username).orElse(null);
            boolean passwordOk = account != null
                    && tokenHasher.hashPassword(rawPassword, account.passwordSalt())
                    .equals(account.passwordHash());

            if (!passwordOk) {
                int failures = state.failureCount() + 1;
                int max = properties.getMaxLoginFailures();
                Instant lockedUntil = null;
                String detail;
                if (failures >= max) {
                    lockedUntil = now.plusSeconds(properties.getLockDurationSeconds());
                    detail = "failure " + failures + "/" + max + " -> locked until " + lockedUntil;
                } else {
                    detail = "failure " + failures + "/" + max;
                }
                loginFailureStore.save(username,
                        new LoginFailureStore.FailureState(failures, lockedUntil));
                auditService.record("LOGIN", username, null, "DENIED",
                        com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason.BAD_CREDENTIALS,
                        detail);
                return TokenIssued.fail(
                        com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason.BAD_CREDENTIALS,
                        "invalid credentials");
            }

            // 成功：清零失败计数并签发凭证
            loginFailureStore.reset(username);
            TokenIssued issued = tokenService.issueForLogin(username, account.roles());
            auditService.record("LOGIN", username, issued.sessionId(), "SUCCESS",
                    com.github.h3yow.sessionaccesscontroljava.auth.model.DecisionReason.ALLOWED,
                    "login success, session issued");
            return issued;
        });
    }

    Instant now() {
        return clock.instant();
    }
}
