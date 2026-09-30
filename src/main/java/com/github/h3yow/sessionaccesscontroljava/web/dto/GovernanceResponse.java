package com.github.h3yow.sessionaccesscontroljava.web.dto;

/** 会话治理写操作（单条撤销 / 撤销其它）的统一响应。 */
public record GovernanceResponse(
        boolean success,
        String reason,
        String message,
        int revokedCount
) {
}
