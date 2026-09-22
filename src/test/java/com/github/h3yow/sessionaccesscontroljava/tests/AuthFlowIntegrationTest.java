package com.github.h3yow.sessionaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端 HTTP 测试：覆盖签发 -> 访问 -> 刷新轮换 -> 重放整链失效 -> 撤销，
 * 以及默认拒绝、权限不足、登录锁定、审计可追溯。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthFlowIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(AuthFlowIntegrationTest.class);
    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private JsonNode login(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andReturn();
        return JSON.readTree(result.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("完整链路：登录-访问-权限区分-刷新-重放-撤销-审计")
    void fullFlowOverHttp() throws Exception {
        // 1) 未认证访问 -> 401 UNAUTHENTICATED
        MvcResult noAuth = mockMvc.perform(get("/api/demo/profile"))
                .andExpect(status().isUnauthorized()).andReturn();
        JsonNode noAuthBody = JSON.readTree(noAuth.getResponse().getContentAsString());
        log.info("[http] 未认证访问 profile -> status=401 reason={}", noAuthBody.path("reason").asText());
        assertEquals("UNAUTHENTICATED", noAuthBody.path("reason").asText());

        // 2) bob(USER) 登录
        JsonNode bobLogin = login("bob", "password-123");
        assertTrue(bobLogin.path("success").asBoolean());
        String bobAccess = bobLogin.path("accessToken").asText();
        String bobRefresh = bobLogin.path("refreshToken").asText();
        String sessionId = bobLogin.path("sessionId").asText();
        log.info("[http] bob 登录成功 session={}", sessionId);

        // 3) bob 访问 profile 允许；访问 admin 权限不足 -> 403 INSUFFICIENT_PERMISSION
        mockMvc.perform(get("/api/demo/profile").header("Authorization", "Bearer " + bobAccess))
                .andExpect(status().isOk());
        MvcResult forbidden = mockMvc.perform(get("/api/demo/admin")
                        .header("Authorization", "Bearer " + bobAccess))
                .andExpect(status().isForbidden()).andReturn();
        JsonNode forbidBody = JSON.readTree(forbidden.getResponse().getContentAsString());
        log.info("[http] bob 访问 admin -> status=403 reason={}", forbidBody.path("reason").asText());
        assertEquals("INSUFFICIENT_PERMISSION", forbidBody.path("reason").asText());

        // 4) 默认拒绝：访问未声明路径 -> 403
        MvcResult undeclared = mockMvc.perform(get("/api/whatever/secret")
                        .header("Authorization", "Bearer " + bobAccess))
                .andExpect(status().isForbidden()).andReturn();
        JsonNode undeclaredBody = JSON.readTree(undeclared.getResponse().getContentAsString());
        log.info("[http] 未声明路径 -> status=403 reason={}", undeclaredBody.path("reason").asText());
        assertEquals("INSUFFICIENT_PERMISSION", undeclaredBody.path("reason").asText());

        // 5) 刷新轮换成功
        MvcResult refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + bobRefresh + "\"}"))
                .andExpect(status().isOk()).andReturn();
        JsonNode refreshed = JSON.readTree(refreshResult.getResponse().getContentAsString());
        String newAccess = refreshed.path("accessToken").asText();
        String newRefresh = refreshed.path("refreshToken").asText();
        log.info("[http] 刷新成功，新 accessToken={}...", newAccess.substring(0, 8));
        mockMvc.perform(get("/api/demo/profile").header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isOk());

        // 6) 旧刷新凭证重放 -> 409 REFRESH_TOKEN_REUSED
        MvcResult replay = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + bobRefresh + "\"}"))
                .andExpect(status().isConflict()).andReturn();
        JsonNode replayBody = JSON.readTree(replay.getResponse().getContentAsString());
        log.info("[http] 旧刷新凭证重放 -> status=409 reason={}", replayBody.path("reason").asText());
        assertEquals("REFRESH_TOKEN_REUSED", replayBody.path("reason").asText());

        // 7) 整链失效：刚刷新出的访问凭证 -> 401 REVOKED
        MvcResult afterReplay = mockMvc.perform(get("/api/demo/profile")
                        .header("Authorization", "Bearer " + newAccess))
                .andExpect(status().isUnauthorized()).andReturn();
        JsonNode afterReplayBody = JSON.readTree(afterReplay.getResponse().getContentAsString());
        log.info("[http] 重放后新访问凭证 -> status=401 reason={}", afterReplayBody.path("reason").asText());
        assertEquals("REVOKED", afterReplayBody.path("reason").asText());

        // 8) 新刷新凭证也已撤销 -> 401 REVOKED（与重放原因区分）
        MvcResult refreshAfterReplay = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + newRefresh + "\"}"))
                .andExpect(status().isUnauthorized()).andReturn();
        JsonNode rarBody = JSON.readTree(refreshAfterReplay.getResponse().getContentAsString());
        log.info("[http] 重放后新刷新凭证 -> reason={}", rarBody.path("reason").asText());
        assertEquals("REVOKED", rarBody.path("reason").asText());

        // 9) 审计可追溯：alice(ADMIN) 登录后查询审计记录
        JsonNode aliceLogin = login("alice", "password-123");
        String aliceAccess = aliceLogin.path("accessToken").asText();
        MvcResult audits = mockMvc.perform(get("/api/demo/audits")
                        .header("Authorization", "Bearer " + aliceAccess))
                .andExpect(status().isOk()).andReturn();
        JsonNode auditArray = JSON.readTree(audits.getResponse().getContentAsString());
        assertTrue(auditArray.isArray());
        assertTrue(auditArray.size() > 5, "应记录全部认证/授权判定，实际=" + auditArray.size());
        boolean hasReplay = false;
        for (JsonNode e : auditArray) {
            if ("REFRESH_TOKEN_REUSED".equals(e.path("reason").asText())) {
                hasReplay = true;
            }
        }
        log.info("[http] 审计记录数={} 含重放记录={}", auditArray.size(), hasReplay);
        assertTrue(hasReplay, "审计中必须能追溯到重放判定");
    }

    @Test
    @DisplayName("主动撤销（登出）后凭证立即失效")
    void logoutRevokesImmediately() throws Exception {
        JsonNode t = login("bob", "password-123");
        String access = t.path("accessToken").asText();
        String session = t.path("sessionId").asText();

        mockMvc.perform(get("/api/demo/profile").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + access)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + session + "\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/demo/profile").header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized());
        log.info("[http] 登出后再次访问 profile -> 401，撤销即时生效");
    }

    @Test
    @DisplayName("连续失败登录触发 HTTP 429 锁定")
    void lockoutOverHttp() throws Exception {
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"username\":\"carol\",\"password\":\"wrong\"}"));
        }
        MvcResult locked = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"carol\",\"password\":\"password-123\"}"))
                .andExpect(status().isTooManyRequests()).andReturn();
        JsonNode body = JSON.readTree(locked.getResponse().getContentAsString());
        log.info("[http] 锁定窗口内登录 -> status=429 reason={}", body.path("reason").asText());
        assertEquals("ACCOUNT_LOCKED", body.path("reason").asText());
    }
}
