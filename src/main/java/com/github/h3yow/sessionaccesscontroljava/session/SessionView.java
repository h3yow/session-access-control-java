package com.github.h3yow.sessionaccesscontroljava.session;

import java.time.Instant;

/**
 * 会话列表中的单条会话视图（面向用户的会话治理）。
 *
 * 刻意只包含识别信息，绝不包含任何凭证内容（access/refresh token 均不出现）：
 * - sessionId      ：会话标识，用于精确撤销某一条
 * - createdAt      ：登录时间（哪次登录）
 * - lastActivityAt ：最近一次访问/刷新活动时间
 * - current        ：是否为发起本次查询的会话
 * - state          ：会话状态（列表仅返回存活会话，固定 ACTIVE）
 */
public record SessionView(
        String sessionId,
        String username,
        Instant createdAt,
        Instant lastActivityAt,
        boolean current,
        SessionState state
) {
}
