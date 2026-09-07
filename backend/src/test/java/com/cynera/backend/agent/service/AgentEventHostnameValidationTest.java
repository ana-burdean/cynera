package com.cynera.backend.agent.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.event.service.EventIngestionService;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class AgentEventHostnameValidationTest {

    private final AgentService agentService =
            mock(AgentService.class);

    private final AgentEventValidationService validationService =
            new AgentEventValidationService();

    private final EventIngestionService eventIngestionService =
            mock(EventIngestionService.class);

    private final AgentEventService agentEventService =
            new AgentEventService(
                    agentService,
                    validationService,
                    eventIngestionService
            );

    @Test
    void shouldRejectEventWhenHostnameDoesNotMatchAgent() {

        Instant timestamp =
                Instant.parse("2026-09-04T07:00:00Z");

        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token",
                true,
                timestamp
        );

        AgentEventRequest request =
                new AgentEventRequest(
                        "PROCESS_START",
                        "OTHER-HOST",
                        "alice",
                        "powershell.exe",
                        "explorer.exe",
                        timestamp
                );

        when(agentService.findByToken("agent-token"))
                .thenReturn(agent);

        assertThrows(
                IllegalArgumentException.class,
                () -> agentEventService.ingest(
                        "agent-token",
                        request
                )
        );

        verify(eventIngestionService, never())
                .ingest(any());
    }
}