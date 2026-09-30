package com.github.h3yow.sessionaccesscontroljava.governance;

/** 会话治理操作（列表/定向撤销/批量撤销）的结果原因。 */
public enum GovernanceOutcome {
    LIST_SUCCESS,
    REVOKE_SESSION_SUCCESS,
    REVOKE_OTHERS_SUCCESS,
    SESSION_NOT_FOUND,
    SESSION_NOT_OWNED,
    SESSION_NOT_ACTIVE
}
