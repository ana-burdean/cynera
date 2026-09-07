package com.cynera.backend.agent.controller;

import com.cynera.backend.agent.dto.FileTelemetry;
import com.cynera.backend.agent.service.AgentService;
import com.cynera.backend.auth.security.JwtService;
import com.cynera.backend.auth.service.UserService;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.file.service.FileTelemetryService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AgentFileController.class)
@AutoConfigureMockMvc(addFilters = false)
class AgentFileControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private FileTelemetryService fileTelemetryService;

    @MockitoBean
    private AgentService agentService;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private UserService userService;

    @Test
    void shouldIngestFileTelemetry() throws Exception {

        EventIngestionResponse response =
                new EventIngestionResponse(
                        1L,
                        "FILE_CREATED",
                        "WIN-FILE-01",
                        Instant.parse("2026-09-07T10:00:00Z")
                );

        when(fileTelemetryService.ingest(
                eq("file-agent-token"),
                any(FileTelemetry.class)
        )).thenReturn(response);

        String json = """
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
                        .header("X-Agent-Token", "file-agent-token")
                        .contentType("application/json")
                        .content(json)
        ).andExpect(status().isCreated());
    }
}
