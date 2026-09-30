package com.github.h3yow.sessionaccesscontroljava.web.dto;

import java.util.List;

/** 会话列举响应。 */
public record SessionListResponse(
        boolean success,
        String reason,
        String message,
        List<SessionInfoResponse> sessions
) {
}
