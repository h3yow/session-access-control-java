package com.github.h3yow.sessionaccesscontroljava.session;

/**
 * 会话链状态。
 *
 * ACTIVE       正常存活（访问/刷新均放行，受闲置超时惰性约束）
 * REVOKED      用户/系统主动撤销，终态，不可重新激活
 * IDLE_TIMEOUT 闲置超时：超过闲置窗口既无访问也无刷新，惰性转入，终态
 * EVICTED      容量超限被淘汰（同一用户活跃会话数超过上限时淘汰最久未活动者），终态
 * EXPIRED      刷新凭证到达绝对过期时间后惰性转入，终态（与闲置超时可区分）
 */
public enum SessionState {
    ACTIVE,
    REVOKED,
    IDLE_TIMEOUT,
    EVICTED,
    EXPIRED
}
