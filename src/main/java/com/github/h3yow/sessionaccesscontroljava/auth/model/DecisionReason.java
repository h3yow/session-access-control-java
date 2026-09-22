package com.github.h3yow.sessionaccesscontroljava.auth.model;

/**
 * 可区分的判定原因。认证与授权的每一种结果都有独立原因码，禁止静默放行。
 */
public enum DecisionReason {

    /** 允许访问。 */
    ALLOWED,

    /** 未携带或无法识别凭证（未认证）。 */
    UNAUTHENTICATED,

    /** 凭证已过期。 */
    EXPIRED,

    /** 会话已撤销（含主动撤销、刷新重放导致的整链失效）。 */
    REVOKED,

    /** 权限不足，或命中默认拒绝策略。 */
    INSUFFICIENT_PERMISSION,

    /** 登录凭证错误（用户名或密码不正确）。 */
    BAD_CREDENTIALS,

    /** 账户因连续失败登录被临时抑制。 */
    ACCOUNT_LOCKED,

    /** 刷新凭证不存在 / 无法识别。 */
    TOKEN_UNKNOWN,

    /** 已轮换的旧刷新凭证被再次使用（重放），会话链整体失效。 */
    REFRESH_TOKEN_REUSED
}
