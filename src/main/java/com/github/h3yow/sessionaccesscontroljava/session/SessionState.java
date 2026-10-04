package com.github.h3yow.sessionaccesscontroljava.session;

/**
 * 会话链状态。
 *
 * ACTIVE 是唯一的存活状态，其余均为终态（不可被重新激活）：
 * - REVOKED      ：用户主动撤销，或检测到刷新凭证复用
 * - IDLE_TIMEOUT ：闲置超时自动失效（一段时间既无访问也无刷新）
 * - EVICTED      ：超过单用户活跃会话容量上限被淘汰
 * - EXPIRED      ：长期登录凭证（链上 refresh 凭证）到达绝对过期时间
 *
 * 绝对过期在任何一个入口（会话名单、访问、刷新）被触碰时都经同一条
 * SessionRepository#evaluateLifecycle 规则懒收敛：绝对过期优先于闲置，
 * 因此"绝对有效期已到、闲置窗口还没到"的会话绝不会停留在 ACTIVE，
 * 名单不展示、访问（即便其短期访问凭证表面未到期）与刷新都按 SESSION_EXPIRED /
 * REFRESH_TOKEN_EXPIRED 拒绝，且 EXPIRED 为终态，任何后续请求都不能将其复活。
 */
public enum SessionState {
    ACTIVE,
    REVOKED,
    IDLE_TIMEOUT,
    EVICTED,
    EXPIRED
}
