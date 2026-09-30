package com.github.h3yow.sessionaccesscontroljava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端：登录 -> 访问 -> 刷新轮换 -> 旧凭证复用 -> 全链失效 的完整 HTTP 链路，
 * 并断言未认证/权限不足/复用等返回体中的 reason 彼此可区分。
 */
@SpringBootTest
@AutoConfigureMockMvc
class HttpEndToEndTests {

    private static final Logger log = LoggerFactory.getLogger(HttpEndToEndTests.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private JsonNode json(MvcResult result) throws Exception {
        return MAPPER.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void fullLifecycleOverHttp() throws Exception {
        // 1. 无凭证访问 -> 401 MISSING_CREDENTIAL
        MvcResult missing = mockMvc.perform(get("/api/resources/profile"))
                .andExpect(status().isUnauthorized()).andReturn();
        JsonNode missingBody = json(missing);
        log.info("HTTP no-token: status=401 reason={}", missingBody.get("reason").asText());
        assertEquals("MISSING_CREDENTIAL", missingBody.get("reason").asText());

        // 2. 错误密码 -> 401 INVALID_CREDENTIALS
        MvcResult badLogin = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"alice","password":"wrong"}
                                """))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("HTTP bad-login: reason={}", json(badLogin).get("reason").asText());
        assertEquals("INVALID_CREDENTIALS", json(badLogin).get("reason").asText());

        // 3. 正确登录
        MvcResult login = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"alice","password":"password123"}
                                """))
                .andExpect(status().isOk()).andReturn();
        JsonNode loginBody = json(login);
        String access = loginBody.get("accessToken").asText();
        String refresh = loginBody.get("refreshToken").asText();
        log.info("HTTP login: reason={} accessPrefix={}", loginBody.get("reason").asText(), access.substring(0, 6));

        // 4. 带凭证访问允许的资源
        mockMvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());

        // 5. 权限不足 -> 403 INSUFFICIENT_PERMISSION（与 401 可区分）
        MvcResult forbidden = mockMvc.perform(get("/api/resources/admin/dashboard")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden()).andReturn();
        log.info("HTTP forbidden: reason={}", json(forbidden).get("reason").asText());
        assertEquals("INSUFFICIENT_PERMISSION", json(forbidden).get("reason").asText());

        // 6. 刷新轮换
        MvcResult refreshed = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isOk()).andReturn();
        JsonNode refreshBody = json(refreshed);
        String newRefresh = refreshBody.get("refreshToken").asText();
        assertNotEquals(refresh, newRefresh);
        log.info("HTTP refresh: reason={} rotated", refreshBody.get("reason").asText());

        // 7. 旧 refresh 复用 -> 401 REFRESH_TOKEN_REUSED
        MvcResult reuse = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + refresh + "\"}"))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("HTTP reuse: reason={}", json(reuse).get("reason").asText());
        assertEquals("REFRESH_TOKEN_REUSED", json(reuse).get("reason").asText());

        // 8. 链已失效：新 refresh -> SESSION_REVOKED；旧 access -> TOKEN_REVOKED
        MvcResult deadRefresh = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + newRefresh + "\"}"))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("SESSION_REVOKED", json(deadRefresh).get("reason").asText());

        MvcResult deadAccess = mockMvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized()).andReturn();
        log.info("HTTP access-after-chain-revoked: reason={}", json(deadAccess).get("reason").asText());
        assertEquals("TOKEN_REVOKED", json(deadAccess).get("reason").asText());
    }

    @Test
    void unknownAndLockedReasonsAreDistinguishable() throws Exception {
        MvcResult unknownRefresh = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"nope\"}"))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("REFRESH_TOKEN_UNKNOWN", json(unknownRefresh).get("reason").asText());
        log.info("HTTP unknown-refresh: reason={}", json(unknownRefresh).get("reason").asText());

        // 连续 5 次失败 -> 423 LOCKED + ACCOUNT_LOCKED
        // 专用用户名（不存在），避免与其他 @SpringBootTest 类共享上下文时的锁定状态串扰
        String bobBad = "{\"username\":\"lockme-http-e2e\",\"password\":\"wrong\"}";
        for (int i = 0; i < 4; i++) {
            mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON).content(bobBad))
                    .andExpect(status().isUnauthorized());
        }
        MvcResult locked = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(bobBad))
                .andExpect(status().isLocked()).andReturn();
        log.info("HTTP locked: status=423 reason={}", json(locked).get("reason").asText());
        assertEquals("ACCOUNT_LOCKED", json(locked).get("reason").asText());
    }
}
