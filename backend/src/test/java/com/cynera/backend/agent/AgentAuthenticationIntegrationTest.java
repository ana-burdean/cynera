package com.cynera.backend.agent;

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

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AgentAuthenticationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AgentRepository agentRepository;

    @BeforeEach
    void cleanDatabase() {
        agentRepository.deleteAll();
    }

    @Test
    void protectedEndpointShouldRejectRequestWithoutAgentToken()
            throws Exception {

        mockMvc.perform(
                        get("/api/v1/events")
                )
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointShouldAcceptValidAgentToken()
            throws Exception {

        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token",
                true,
                Instant.now()
        );

        agentRepository.save(agent);

        mockMvc.perform(
                        get("/api/v1/events")
                                .header(
                                        "X-Agent-Token",
                                        "agent-token"
                                )
                )
                .andExpect(status().isOk());
    }

    @Test
    void protectedEndpointShouldRejectInvalidAgentToken()
            throws Exception {

        mockMvc.perform(
                        get("/api/v1/events")
                                .header(
                                        "X-Agent-Token",
                                        "invalid-token"
                                )
                )
                .andExpect(status().isUnauthorized());
    }
}