package com.github.h3yow.sessionaccesscontroljava.auth;

import com.github.h3yow.sessionaccesscontroljava.token.TokenPair;

/** 认证操作结果：原因 + 成功时携带的凭证对。 */
public record AuthResult(AuthOutcome outcome, TokenPair tokens, String message) {

    public static AuthResult failure(AuthOutcome outcome, String message) {
        return new AuthResult(outcome, null, message);
    }

    public static AuthResult success(AuthOutcome outcome, TokenPair tokens, String message) {
        return new AuthResult(outcome, tokens, message);
    }

    public boolean isSuccess() {
        return tokens != null;
    }
}
