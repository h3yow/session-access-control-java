package com.github.h3yow.sessionaccesscontroljava.web.dto;

public record ErrorResponse(boolean success, String reason, String message) {
}
