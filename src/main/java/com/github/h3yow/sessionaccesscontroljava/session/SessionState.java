package com.github.h3yow.sessionaccesscontroljava.session;

/**
 * 会话链状态。
 *
 * ACTIVE 是唯一的存活状态，其余均为终态（不可被重新激活）：
 * - REVOKED      ：用户主动撤销，或检测到刷新凭证复用
 * - IDLE_TIMEOUT ：闲置超时自动失效（一段时间既无访问也无刷新）
 * - EVICTED      ：超过单用户活跃会话容量上限被淘汰
 * - EXPIRED      ：刷新凭证到达绝对过期时间
 */
public enum SessionState {
    ACTIVE,
    REVOKED,
    IDLE_TIMEOUT,
    EVICTED,
    EXPIRED
}
