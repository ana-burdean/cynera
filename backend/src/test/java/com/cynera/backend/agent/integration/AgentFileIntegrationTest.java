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
class AgentFileIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AgentRepository agentRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Autowired
    private DetectionRepository detectionRepository;

    private static final String AGENT_TOKEN = "file-test-agent-token";

    @BeforeEach
    void setUp() {
        detectionRepository.deleteAll();
        securityEventRepository.deleteAll();
        agentRepository.deleteAll();

        Agent agent = new Agent(
                "file-test-agent",
                "WIN-FILE-01",
                AGENT_TOKEN,
                true,
                Instant.parse("2026-09-07T09:00:00Z")
        );

        agentRepository.save(agent);
    }

    @Test
    void shouldIngestFileTelemetryWithValidAgentToken() throws Exception {
        String request = """
                {
                  "hostname": "WIN-FILE-01",
                  "filePath": "C:\\\\temp\\\\malware.txt",
                  "fileAction": "CREATED",
                  "fileSize": 2048,
                  "fileHash": "abc123",
                  "username": "ana",
                  "processName": "explorer.exe",
                  "parentProcessName": null,
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/files")
                                .header("X-Agent-Token", AGENT_TOKEN)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.eventType").value("FILE_CREATED"))
                .andExpect(jsonPath("$.hostname").value("WIN-FILE-01"));

        SecurityEvent savedEvent = securityEventRepository.findAll()
                .stream()
                .findFirst()
                .orElseThrow();

        assertEquals("FILE_CREATED", savedEvent.getEventType());
        assertEquals("C:\\temp\\malware.txt", savedEvent.getFilePath());
        assertEquals("CREATED", savedEvent.getFileAction());
        assertEquals(2048L, savedEvent.getFileSize());
        assertEquals("abc123", savedEvent.getFileHash());
    }

    @Test
    void shouldRejectFileTelemetryWithoutAgentToken() throws Exception {
        String request = """
                {
                  "hostname": "WIN-FILE-01",
                  "filePath": "C:\\\\temp\\\\test.txt",
                  "fileAction": "CREATED",
                  "fileSize": 100,
                  "fileHash": "hash",
                  "username": "ana",
                  "processName": "explorer.exe",
                  "parentProcessName": null,
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/files")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectFileTelemetryWithInvalidAgentToken() throws Exception {
        String request = """
                {
                  "hostname": "WIN-FILE-01",
                  "filePath": "C:\\\\temp\\\\test.txt",
                  "fileAction": "CREATED",
                  "fileSize": 100,
                  "fileHash": "hash",
                  "username": "ana",
                  "processName": "explorer.exe",
                  "parentProcessName": null,
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
    }
}