package com.github.h3yow.sessionaccesscontroljava.governance;

import java.util.List;

/** 治理操作结果：成功列表时携带视图，撤销操作携带受影响会话数。 */
public record GovernanceResult(
        GovernanceOutcome outcome,
        List<SessionView> sessions,
        int affected,
        String message
) {
    public static GovernanceResult list(List<SessionView> sessions) {
        return new GovernanceResult(GovernanceOutcome.LIST_SUCCESS, List.copyOf(sessions), 0, "sessions listed");
    }

    public static GovernanceResult ok(GovernanceOutcome outcome, int affected, String message) {
        return new GovernanceResult(outcome, List.of(), affected, message);
    }

    public static GovernanceResult failure(GovernanceOutcome outcome, String message) {
        return new GovernanceResult(outcome, List.of(), 0, message);
    }

    public boolean isSuccess() {
        return outcome == GovernanceOutcome.LIST_SUCCESS
                || outcome == GovernanceOutcome.REVOKE_SESSION_SUCCESS
                || outcome == GovernanceOutcome.REVOKE_OTHERS_SUCCESS;
    }
}
