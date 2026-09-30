package com.github.h3yow.sessionaccesscontroljava.governance;

/** 会话治理操作（列举 / 单条撤销 / 撤销其它）的可区分结果原因。 */
public enum GovernanceOutcome {
    SESSIONS_LISTED,
    SESSION_REVOKED,
    SESSIONS_REVOKED_OTHERS,
    SESSION_NOT_FOUND,
    /** 目标会话属于其他用户：查看与撤销均被明确拒绝。 */
    SESSION_FORBIDDEN
}
