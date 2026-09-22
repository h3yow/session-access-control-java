package com.github.h3yow.sessionaccesscontroljava.web;

import com.github.h3yow.sessionaccesscontroljava.access.RequirePermission;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 受保护资源端点。
 * 每个端点通过 {@link RequirePermission} 显式声明所需权限；
 * 未标注的 /api/** 路径默认拒绝。
 */
@RestController
@RequestMapping("/api/resources")
public class ProtectedApiController {

    /** 任何已认证用户均可访问（所有内置角色均含 profile:read）。 */
    @GetMapping("/profile")
    @RequirePermission("profile:read")
    public Map<String, Object> profile(HttpServletRequest request) {
        return Map.of(
                "resource", "profile",
                "username", request.getAttribute("username"),
                "sessionId", request.getAttribute("sessionId"));
    }

    /** 仅 ROLE_ADMIN 可访问。 */
    @GetMapping("/admin/dashboard")
    @RequirePermission("admin:read")
    public Map<String, Object> adminDashboard(HttpServletRequest request) {
        return Map.of(
                "resource", "admin-dashboard",
                "username", request.getAttribute("username"));
    }

    /** 仅 ROLE_FINANCE 可访问。 */
    @GetMapping("/reports/finance")
    @RequirePermission("finance:read")
    public Map<String, Object> financeReport(HttpServletRequest request) {
        return Map.of(
                "resource", "finance-report",
                "username", request.getAttribute("username"));
    }
}
