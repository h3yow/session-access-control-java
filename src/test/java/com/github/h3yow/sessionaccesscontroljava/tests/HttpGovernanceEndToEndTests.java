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
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 会话治理端点的 HTTP 端到端：
 * - 未认证 401；列表条目不含任何凭证；
 * - 定向撤销 200、已终态 409、不存在 404；
 * - 越权撤销他人会话 403 SESSION_NOT_OWNED；
 * - revoke-others 保留当前会话；撤销后该会话访问 401 SESSION_REVOKED/TOKEN_REVOKED。
 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class HttpGovernanceEndToEndTests {

    private static final Logger log = LoggerFactory.getLogger(HttpGovernanceEndToEndTests.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private JsonNode json(MvcResult result) throws Exception {
        return MAPPER.readTree(result.getResponse().getContentAsString());
    }

    private String login(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk()).andReturn();
        return result.getResponse().getContentAsString();
    }

    private record Creds(String access, String refresh, String sessionIdFromResource) {
    }

    private Creds loginCreds(String username, String password) throws Exception {
        JsonNode body = MAPPER.readTree(login(username, password));
        return new Creds(body.get("accessToken").asText(), body.get("refreshToken").asText(), null);
    }

    @Test
    void sessionsEndpointsEnforceAuthAndNeverLeakTokens() throws Exception {
        // 未认证 -> 401
        mockMvc.perform(get("/api/sessions")).andExpect(status().isUnauthorized());

        Creds alice = loginCreds("alice", "password123");
        MvcResult list = mockMvc.perform(get("/api/sessions")
                        .header("Authorization", "Bearer " + alice.access()))
                .andExpect(status().isOk()).andReturn();
        JsonNode listBody = json(list);
        assertEquals("LIST_SUCCESS", listBody.get("outcome").asText());
        JsonNode sessions = listBody.get("sessions");
        assertEquals(1, sessions.size());
        JsonNode first = sessions.get(0);
        log.info("HTTP sessions list entry keys={}", first.fieldNames());
        assertFalse(first.has("accessToken"));
        assertFalse(first.has("refreshToken"));
        assertFalse(first.has("currentRefreshToken"));
        assertEquals(true, first.get("current").asBoolean());
    }

    @Test
    void revokeOneOverHttpAndCrossUserForbidden() throws Exception {
        Creds alice1 = loginCreds("alice", "password123");
        Creds alice2 = loginCreds("alice", "password123");
        Creds bob = loginCreds("bob", "bob123");

        // 找到 alice 两个会话 id（用她自己任一端列出，按 current 区分）
        JsonNode list = json(mockMvc.perform(get("/api/sessions")
                        .header("Authorization", "Bearer " + alice2.access()))
                .andExpect(status().isOk()).andReturn());
        String alice2Id = null;
        String alice1Id = null;
        for (JsonNode node : list.get("sessions")) {
            if (node.get("current").asBoolean()) {
                alice2Id = node.get("sessionId").asText();
            } else {
                alice1Id = node.get("sessionId").asText();
            }
        }
        // bob 越权撤销 alice 的会话：治理服务调用前不会发生——bob 具备 session:manage，
        // 因此请求到达服务层，由归属校验拒绝 -> 403 SESSION_NOT_OWNED（outcome 在治理响应体中）
        MvcResult cross = mockMvc.perform(post("/api/sessions/" + alice1Id + "/revoke")
                        .header("Authorization", "Bearer " + bob.access()))
                .andExpect(status().isForbidden()).andReturn();
        JsonNode crossBody = json(cross);
        log.info("HTTP cross-user revoke: outcome={}", crossBody.get("outcome").asText());
        assertEquals("SESSION_NOT_OWNED", crossBody.get("outcome").asText());

        // alice 自己撤销另一台设备 -> 200
        MvcResult revoked = mockMvc.perform(post("/api/sessions/" + alice1Id + "/revoke")
                        .header("Authorization", "Bearer " + alice2.access()))
                .andExpect(status().isOk()).andReturn();
        assertEquals("REVOKE_SESSION_SUCCESS", json(revoked).get("outcome").asText());

        // 重复撤销 -> 409 SESSION_NOT_ACTIVE
        MvcResult again = mockMvc.perform(post("/api/sessions/" + alice1Id + "/revoke")
                        .header("Authorization", "Bearer " + alice2.access()))
                .andExpect(status().isConflict()).andReturn();
        assertEquals("SESSION_NOT_ACTIVE", json(again).get("outcome").asText());

        // 不存在 id -> 404
        mockMvc.perform(post("/api/sessions/no-such-id/revoke")
                        .header("Authorization", "Bearer " + alice2.access()))
                .andExpect(status().isNotFound());

        // 被撤销端访问 -> 401（TOKEN_REVOKED）
        MvcResult deadAccess = mockMvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + alice1.access()))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("TOKEN_REVOKED", json(deadAccess).get("reason").asText());
        // 当前端仍活
        mockMvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + alice2.access()))
                .andExpect(status().isOk());
    }

    @Test
    void revokeOthersOverHttpKeepsCurrent() throws Exception {
        Creds a = loginCreds("alice", "password123");
        Creds b = loginCreds("alice", "password123");
        Creds c = loginCreds("alice", "password123");

        // 以 b 为当前端
        MvcResult result = mockMvc.perform(post("/api/sessions/revoke-others")
                        .header("Authorization", "Bearer " + b.access()))
                .andExpect(status().isOk()).andReturn();
        JsonNode body = json(result);
        log.info("HTTP revoke-others: outcome={} affected={}",
                body.get("outcome").asText(), body.get("affected").asInt());
        assertEquals("REVOKE_OTHERS_SUCCESS", body.get("outcome").asText());
        assertEquals(2, body.get("affected").asInt());

        mockMvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + a.access()))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + c.access()))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/resources/profile")
                        .header("Authorization", "Bearer " + b.access()))
                .andExpect(status().isOk());
    }
}
