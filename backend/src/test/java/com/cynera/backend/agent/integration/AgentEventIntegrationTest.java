package com.cynera.backend.agent.integration;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.repository.AgentRepository;
import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.repository.DetectionRepository;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AgentEventIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AgentRepository agentRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private DetectionRepository detectionRepository;

    @BeforeEach
    void setUp() {
        detectionRepository.deleteAll();
        securityEventRepository.deleteAll();
        agentRepository.deleteAll();
    }

    @Test
    void shouldIngestAgentEventAndCreateDetection() throws Exception {
        Agent agent = agentRepository.save(
                new Agent(
                        "agent-integration",
                        "HOST-INTEGRATION",
                        "integration-token",
                        true,
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
                                  "hostname": "HOST-INTEGRATION",
                                  "username": "alice",
                                  "processName": "powershell.exe",
                                  "parentProcessName": "explorer.exe"
                                }
                                """)
                )
                .andExpect(status().isCreated());

        List<SecurityEvent> events = securityEventRepository.findAll();

        assertEquals(1, events.size());
        assertEquals(
                "PROCESS_START",
                events.getFirst().getEventType()
        );
        assertEquals(
                "HOST-INTEGRATION",
                events.getFirst().getHostname()
        );

        List<Detection> detections = detectionRepository.findAll();

        assertFalse(detections.isEmpty());
        assertEquals(
                events.getFirst().getId(),
                detections.getFirst().getEvent().getId()
        );
    }
}