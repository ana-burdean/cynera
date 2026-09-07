package com.cynera.backend.agent.integration;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.repository.AgentRepository;
import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.repository.DetectionRepository;
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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AgentEventDetectionIntegrationTest {

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
    void shouldDetectSuspiciousCmdEventFromAgent() throws Exception {
        Agent agent = agentRepository.save(
                new Agent(
                        "agent-detection",
                        "HOST-DETECTION",
                        "detection-token",
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
                                  "hostname": "HOST-DETECTION",
                                  "username": "alice",
                                  "processName": "cmd.exe",
                                  "parentProcessName": "explorer.exe"
                                }
                                """)
                )
                .andExpect(status().isCreated());

        List<Detection> detections = detectionRepository.findAll();

        assertTrue(
                detections.stream()
                        .anyMatch(detection ->
                                "SUSPICIOUS_CMD".equals(
                                        detection.getRule()
                                )
                        )
        );
    }
}