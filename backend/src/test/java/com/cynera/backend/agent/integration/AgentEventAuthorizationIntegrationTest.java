package com.cynera.backend.agent.integration;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.repository.AgentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AgentEventAuthorizationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AgentRepository agentRepository;

    @BeforeEach
    void setUp() {
        agentRepository.deleteAll();
    }

    @Test
    void shouldRejectEventWithoutAgentToken() throws Exception {
        mockMvc.perform(
                        post("/api/v1/agent/events")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                {
                                  "eventType": "PROCESS_START",
                                  "hostname": "HOST-01"
                                }
                                """)
                )
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectEventWithInvalidAgentToken() throws Exception {
        mockMvc.perform(
                        post("/api/v1/agent/events")
                                .header("X-Agent-Token", "invalid-token")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                {
                                  "eventType": "PROCESS_START",
                                  "hostname": "HOST-01"
                                }
                                """)
                )
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectEventFromDisabledAgent() throws Exception {
        Agent agent = agentRepository.save(
                new Agent(
                        "disabled-agent",
                        "HOST-01",
                        "disabled-token",
                        false,
                        Instant.now()
                )
        );

        mockMvc.perform(
                        post("/api/v1/agent/events")
                                .header("X-Agent-Token", agent.getAgentToken())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                {
                                  "eventType": "PROCESS_START",
                                  "hostname": "HOST-01"
                                }
                                """)
                )
                .andExpect(status().isUnauthorized());
    }
}