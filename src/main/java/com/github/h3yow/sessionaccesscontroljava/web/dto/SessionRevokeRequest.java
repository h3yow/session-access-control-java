package com.github.h3yow.sessionaccesscontroljava.web.dto;

/** 精确撤销某一条会话的请求体。 */
public record SessionRevokeRequest(String sessionId) {
}
