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
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AgentFileDetectionIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AgentRepository agentRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private DetectionRepository detectionRepository;

    private static final String AGENT_TOKEN = "file-detection-test-token";

    @BeforeEach
    void setUp() {
        detectionRepository.deleteAll();
        securityEventRepository.deleteAll();
        agentRepository.deleteAll();

        Agent agent = new Agent(
                "file-detection-agent",
                "WIN-FILE-DETECTION-01",
                AGENT_TOKEN,
                true,
                Instant.parse("2026-09-07T09:00:00Z")
        );

        agentRepository.save(agent);
    }

    @Test
    void shouldCreateDetectionForPowerShellFileTelemetry() throws Exception {
        String request = """
                {
                  "hostname": "WIN-FILE-DETECTION-01",
                  "filePath": "C:\\\\temp\\\\payload.ps1",
                  "fileAction": "CREATED",
                  "fileSize": 4096,
                  "fileHash": "powershell-hash",
                  "username": "ana",
                  "processName": "powershell.exe",
                  "parentProcessName": "explorer.exe",
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/files")
                                .header("X-Agent-Token", AGENT_TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isCreated());

        SecurityEvent savedEvent = securityEventRepository.findAll()
                .stream()
                .findFirst()
                .orElseThrow();

        assertEquals("FILE_CREATED", savedEvent.getEventType());
        assertEquals("C:\\temp\\payload.ps1", savedEvent.getFilePath());

        Detection detection = detectionRepository.findAll()
                .stream()
                .findFirst()
                .orElseThrow();

        assertEquals("SUSPICIOUS_POWERSHELL", detection.getRule());
        assertEquals("MEDIUM", detection.getSeverity().name());
    }

    @Test
    void shouldNotCreateDetectionForNormalFileTelemetry() throws Exception {
        String request = """
                {
                  "hostname": "WIN-FILE-DETECTION-01",
                  "filePath": "C:\\\\temp\\\\document.txt",
                  "fileAction": "CREATED",
                  "fileSize": 1024,
                  "fileHash": "normal-hash",
                  "username": "ana",
                  "processName": "explorer.exe",
                  "parentProcessName": "userinit.exe",
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/files")
                                .header("X-Agent-Token", AGENT_TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isCreated());

        assertEquals(1, securityEventRepository.count());
        assertTrue(detectionRepository.findAll().isEmpty());
    }

    @Test
    void shouldRejectInvalidAgentTokenAndPersistNothing() throws Exception {
        String request = """
                {
                  "hostname": "WIN-FILE-DETECTION-01",
                  "filePath": "C:\\\\temp\\\\malware.txt",
                  "fileAction": "CREATED",
                  "fileSize": 2048,
                  "fileHash": "malware-hash",
                  "username": "ana",
                  "processName": "powershell.exe",
                  "parentProcessName": "explorer.exe",
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/files")
                                .header("X-Agent-Token", "invalid-token")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isUnauthorized());

        assertEquals(0, securityEventRepository.count());
        assertTrue(detectionRepository.findAll().isEmpty());
    }
}