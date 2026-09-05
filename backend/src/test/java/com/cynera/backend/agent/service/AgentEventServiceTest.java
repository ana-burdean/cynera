package com.cynera.backend.agent.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.event.service.EventIngestionService;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class AgentEventServiceTest {

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
    void shouldIngestEventForValidEnabledAgent() {

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
                        "HOST-01",
                        "alice",
                        "powershell.exe",
                        "explorer.exe",
                        timestamp
                );

        EventIngestionResponse expected =
                new EventIngestionResponse(
                        1L,
                        "PROCESS_START",
                        "HOST-01",
                        timestamp
                );

        when(agentService.findByToken("agent-token"))
                .thenReturn(agent);

        when(eventIngestionService.ingest(request))
                .thenReturn(expected);

        EventIngestionResponse result =
                agentEventService.ingest(
                        "agent-token",
                        request
                );

        assertEquals(expected, result);

        verify(agentService)
                .findByToken("agent-token");

        verify(validationService)
                .validateAgentHostname(agent, "HOST-01");

        verify(eventIngestionService)
                .ingest(request);
    }

    @Test
    void shouldRejectDisabledAgent() {

        Instant timestamp =
                Instant.parse("2026-09-04T07:00:00Z");

        Agent agent = new Agent(
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
                .thenReturn(agent);

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
