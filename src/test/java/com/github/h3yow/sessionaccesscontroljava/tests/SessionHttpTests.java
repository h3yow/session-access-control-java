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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** 会话治理端点的 HTTP 端到端：列表、精确撤销、撤销其它、越权 403、未登录 401。 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class SessionHttpTests {

    private static final Logger log = LoggerFactory.getLogger(SessionHttpTests.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private JsonNode json(MvcResult result) throws Exception {
        return MAPPER.readTree(result.getResponse().getContentAsString());
    }

    private String login(String user, String password) throws Exception {
        MvcResult r = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"" + user + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk()).andReturn();
        return json(r).get("accessToken").asText();
    }

    @Test
    void listAndRevokeAndRevokeOthersOverHttp() throws Exception {
        // 未登录访问治理端点 -> 401
        MvcResult missing = mockMvc.perform(get("/api/sessions"))
                .andExpect(status().isUnauthorized()).andReturn();
        assertEquals("MISSING_CREDENTIAL", json(missing).get("reason").asText());

        // alice 两端登录
        String a1 = login("alice", "password123");
        String a2 = login("alice", "password123");

        // 用 a2 查询：2 条，视图中不含任何凭证字段，current 恰有一条且为 a2 所在会话
        MvcResult listResult = mockMvc.perform(get("/api/sessions")
                        .header("Authorization", "Bearer " + a2))
                .andExpect(status().isOk()).andReturn();
        JsonNode list = json(listResult);
        assertEquals(2, list.get("sessions").size());
        boolean hasCredential = list.toString().contains("accessToken")
                || list.toString().contains("refreshToken");
        assertFalse(hasCredential, "会话列表不得包含任何凭证内容");
        int currentCount = 0;
        for (JsonNode s : list.get("sessions")) {
            if (s.get("current").asBoolean()) {
                currentCount++;
            }
        }
        assertEquals(1, currentCount);
        log.info("HTTP sessions list: size=2 无凭证字段 current=1");

        // 取 a1 的 sessionId，用 a2 撤销它
        String a1SessionId = null;
        for (JsonNode s : list.get("sessions")) {
            if (!s.get("current").asBoolean()) {
                a1SessionId = s.get("sessionId").asText();
            }
        }
        MvcResult revokeResult = mockMvc.perform(post("/api/sessions/revoke")
                        .header("Authorization", "Bearer " + a2)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + a1SessionId + "\"}"))
                .andExpect(status().isOk()).andReturn();
        assertEquals("SESSION_REVOKED", json(revokeResult).get("reason").asText());
        log.info("HTTP revoke one: reason=SESSION_REVOKED");

        // a1 立即失效
        mockMvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + a1))
                .andExpect(status().isUnauthorized());

        // 再登录第三台设备 a3，用 a2 撤销"其它" -> 撤销 a3，保留 a2
        String a3 = login("alice", "password123");
        MvcResult others = mockMvc.perform(delete("/api/sessions/others")
                        .header("Authorization", "Bearer " + a2))
                .andExpect(status().isOk()).andReturn();
        JsonNode othersBody = json(others);
        assertEquals("SESSIONS_REVOKED_OTHERS", othersBody.get("reason").asText());
        assertEquals(1, othersBody.get("revokedCount").asInt());
        mockMvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + a3))
                .andExpect(status().isUnauthorized());
        // a2 仍可用
        mockMvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + a2))
                .andExpect(status().isOk());
        log.info("HTTP revoke others: revokedCount=1, 当前会话 a2 保持可用");
    }

    @Test
    void crossUserRevocationOverHttpIsForbidden() throws Exception {
        String aliceAccess = login("alice", "password123");
        String bobAccess = login("bob", "bob123");

        // 拿到 alice 的 sessionId（alice 自己列）
        MvcResult aliceList = mockMvc.perform(get("/api/sessions")
                        .header("Authorization", "Bearer " + aliceAccess))
                .andExpect(status().isOk()).andReturn();
        String aliceSessionId = json(aliceList).get("sessions").get(0).get("sessionId").asText();

        // bob 试图撤销 alice 的会话 -> 403 SESSION_FORBIDDEN
        MvcResult forbidden = mockMvc.perform(post("/api/sessions/revoke")
                        .header("Authorization", "Bearer " + bobAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"" + aliceSessionId + "\"}"))
                .andExpect(status().isForbidden()).andReturn();
        assertEquals("SESSION_FORBIDDEN", json(forbidden).get("reason").asText());
        log.info("HTTP cross-user revoke: status=403 reason=SESSION_FORBIDDEN");

        // 越权未生效：alice 仍可访问
        mockMvc.perform(get("/api/resources/profile").header("Authorization", "Bearer " + aliceAccess))
                .andExpect(status().isOk());

        // 撤销未知 sessionId -> 404 SESSION_NOT_FOUND
        MvcResult notFound = mockMvc.perform(post("/api/sessions/revoke")
                        .header("Authorization", "Bearer " + bobAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"sessionId\":\"missing\"}"))
                .andExpect(status().isNotFound()).andReturn();
        assertEquals("SESSION_NOT_FOUND", json(notFound).get("reason").asText());
        assertTrue(true);
        log.info("HTTP revoke unknown: status=404 reason=SESSION_NOT_FOUND");
    }
}
