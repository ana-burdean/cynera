package com.cynera.backend.agent.controller;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.event.dto.EventIngestionResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AgentEventControllerTest {

    private final AgentEventService agentEventService =
            mock(AgentEventService.class);

    private final AgentEventController controller =
            new AgentEventController(agentEventService);

    private final MockMvc mockMvc =
            MockMvcBuilders
                    .standaloneSetup(controller)
                    .build();

    @Test
    void shouldIngestEventWithValidAgentToken()
            throws Exception {

        Instant timestamp =
                Instant.parse("2026-09-04T07:00:00Z");

        EventIngestionResponse response =
                new EventIngestionResponse(
                        1L,
                        "PROCESS_START",
                        "HOST-01",
                        timestamp
                );

        when(agentEventService.ingest(
                eq("agent-token"),
                any(AgentEventRequest.class)
        )).thenReturn(response);

        mockMvc.perform(
                post("/api/v1/agent/events")
                        .header("X-Agent-Token", "agent-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "eventType": "PROCESS_START",
                                  "hostname": "HOST-01",
                                  "username": "alice",
                                  "processName": "powershell.exe",
                                  "parentProcessName": "explorer.exe",
                                  "timestamp": "2026-09-04T07:00:00Z"
                                }
                                """)
        )
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.eventId").value(1))
                .andExpect(jsonPath("$.eventType")
                        .value("PROCESS_START"))
                .andExpect(jsonPath("$.hostname")
                        .value("HOST-01"));

        verify(agentEventService).ingest(
                eq("agent-token"),
                any(AgentEventRequest.class)
        );
    }
}
