package com.cynera.backend.agent.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.event.service.EventIngestionService;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class DisabledAgentEventTest {

    private final AgentService agentService =
            mock(AgentService.class);

    private final AgentEventValidationService validationService =
            mock(AgentEventValidationService.class);

    private final EventIngestionService eventIngestionService =
            mock(EventIngestionService.class);

    private final AgentEventService agentEventService =
            new AgentEventService(
                    agentService,
                    validationService,
                    eventIngestionService
            );

    @Test
    void shouldRejectEventFromDisabledAgent() {

        Instant timestamp =
                Instant.parse("2026-09-04T07:00:00Z");

        Agent disabledAgent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token",
                false,
                timestamp
        );

        AgentEventRequest request =
                new AgentEventRequest(
                        "PROCESS_START",
                        "HOST-01",
                        "alice",
                        "powershell.exe",
                        "explorer.exe",
                        timestamp
                );

        when(agentService.findByToken("agent-token"))
                .thenReturn(disabledAgent);

        assertThrows(
                IllegalArgumentException.class,
                () -> agentEventService.ingest(
                        "agent-token",
                        request
                )
        );

        verify(validationService, never())
                .validateAgentHostname(any(), any());

        verify(eventIngestionService, never())
                .ingest(any());
    }
}