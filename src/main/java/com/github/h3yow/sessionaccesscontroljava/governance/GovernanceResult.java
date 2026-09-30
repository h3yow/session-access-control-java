package com.github.h3yow.sessionaccesscontroljava.governance;

import com.github.h3yow.sessionaccesscontroljava.session.SessionView;

import java.util.List;

/**
 * 会话治理操作结果：原因 + 可选会话视图负载（列举/撤销计数）。
 * 任何失败都不携带会话信息，避免越权读取到他人会话元数据。
 */
public record GovernanceResult(
        GovernanceOutcome outcome,
        List<SessionView> sessions,
        int revokedCount,
        String message
) {
    public static GovernanceResult listed(List<SessionView> sessions) {
        return new GovernanceResult(GovernanceOutcome.SESSIONS_LISTED, List.copyOf(sessions), 0,
                "active sessions listed");
    }

    public static GovernanceResult revoked(String message) {
        return new GovernanceResult(GovernanceOutcome.SESSION_REVOKED, null, 1, message);
    }

    public static GovernanceResult revokedOthers(int count) {
        return new GovernanceResult(GovernanceOutcome.SESSIONS_REVOKED_OTHERS, null, count,
                "all other sessions revoked, count=" + count);
    }

    public static GovernanceResult failure(GovernanceOutcome outcome, String message) {
        return new GovernanceResult(outcome, null, 0, message);
    }

    public boolean isSuccess() {
        return outcome == GovernanceOutcome.SESSIONS_LISTED
                || outcome == GovernanceOutcome.SESSION_REVOKED
                || outcome == GovernanceOutcome.SESSIONS_REVOKED_OTHERS;
    }
}
