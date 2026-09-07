package com.cynera.backend.agent.integration;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.repository.AgentRepository;
import com.cynera.backend.detection.repository.DetectionRepository;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AgentNetworkIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AgentRepository agentRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private DetectionRepository detectionRepository;

    private static final String AGENT_TOKEN = "network-test-agent-token";

    @BeforeEach
    void setUp() {
        detectionRepository.deleteAll();
        securityEventRepository.deleteAll();
        agentRepository.deleteAll();

        Agent agent = new Agent(
                "network-test-agent",
                "WIN-NET-01",
                AGENT_TOKEN,
                true,
                Instant.parse("2026-09-07T09:00:00Z")
        );

        agentRepository.save(agent);
    }

    @Test
    void shouldIngestNetworkTelemetryWithValidAgentToken() throws Exception {
        String request = """
                {
                  "hostname": "WIN-NET-01",
                  "remoteAddress": "192.168.1.100",
                  "remotePort": 443,
                  "protocol": "TCP",
                  "username": "ana",
                  "processName": "powershell.exe",
                  "parentProcessName": "explorer.exe",
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/network")
                                .header("X-Agent-Token", AGENT_TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.eventType").value("NETWORK_CONNECTION"))
                .andExpect(jsonPath("$.hostname").value("WIN-NET-01"));

        SecurityEvent savedEvent = securityEventRepository.findAll()
                .stream()
                .findFirst()
                .orElseThrow();

        assertEquals("NETWORK_CONNECTION", savedEvent.getEventType());
        assertEquals("WIN-NET-01", savedEvent.getHostname());
        assertEquals("ana", savedEvent.getUsername());
        assertEquals("powershell.exe", savedEvent.getProcessName());
        assertEquals("explorer.exe", savedEvent.getParentProcessName());
        assertEquals("192.168.1.100", savedEvent.getRemoteAddress());
        assertEquals(443, savedEvent.getRemotePort());
        assertEquals("TCP", savedEvent.getNetworkProtocol());
        assertEquals(
                Instant.parse("2026-09-07T10:00:00Z"),
                savedEvent.getTimestamp()
        );
    }

    @Test
    void shouldRejectNetworkTelemetryWithoutAgentToken() throws Exception {
        String request = """
                {
                  "hostname": "WIN-NET-01",
                  "remoteAddress": "192.168.1.100",
                  "remotePort": 443,
                  "protocol": "TCP",
                  "username": "ana",
                  "processName": "powershell.exe",
                  "parentProcessName": "explorer.exe",
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/network")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectNetworkTelemetryWithInvalidAgentToken() throws Exception {
        String request = """
                {
                  "hostname": "WIN-NET-01",
                  "remoteAddress": "192.168.1.100",
                  "remotePort": 443,
                  "protocol": "TCP",
                  "username": "ana",
                  "processName": "powershell.exe",
                  "parentProcessName": "explorer.exe",
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/network")
                                .header("X-Agent-Token", "invalid-network-token")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isUnauthorized());
    }
}
