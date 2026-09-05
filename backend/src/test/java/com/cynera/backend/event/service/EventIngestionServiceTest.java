package com.cynera.backend.event.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.event.dto.EventRequest;
import com.cynera.backend.event.dto.EventResponse;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class EventIngestionServiceTest {

    private final EventService eventService =
            mock(EventService.class);

    private final EventIngestionMapper eventIngestionMapper =
            mock(EventIngestionMapper.class);

    private final EventIngestionService ingestionService =
            new EventIngestionService(
                    eventService,
                    eventIngestionMapper
            );

    @Test
    void shouldIngestAgentEventThroughEventService() {

        Instant timestamp =
                Instant.parse("2026-09-04T07:00:00Z");

        AgentEventRequest agentRequest =
                new AgentEventRequest(
                        "PROCESS_START",
                        "HOST-01",
                        "alice",
                        "powershell.exe",
                        "explorer.exe",
                        timestamp
                );

        EventRequest eventRequest =
                new EventRequest(
                        timestamp,
                        "PROCESS_START",
                        "HOST-01",
                        "alice",
                        "powershell.exe",
                        "explorer.exe"
                );

        EventResponse eventResponse =
                new EventResponse(
                        1L,
                        timestamp,
                        "PROCESS_START",
                        "HOST-01",
                        "alice",
                        "powershell.exe",
                        "explorer.exe"
                );

        EventIngestionResponse ingestionResponse =
                new EventIngestionResponse(
                        1L,
                        "PROCESS_START",
                        "HOST-01",
                        timestamp
                );

        when(eventIngestionMapper.toEventRequest(agentRequest))
                .thenReturn(eventRequest);

        when(eventService.ingestEvent(eventRequest))
                .thenReturn(eventResponse);

        when(eventIngestionMapper.toIngestionResponse(eventResponse))
                .thenReturn(ingestionResponse);

        EventIngestionResponse result =
                ingestionService.ingest(agentRequest);

        assertEquals(1L, result.eventId());
        assertEquals(
                "PROCESS_START",
                result.eventType()
        );
        assertEquals(
                "HOST-01",
                result.hostname()
        );
        assertEquals(timestamp, result.timestamp());

        verify(eventIngestionMapper)
                .toEventRequest(agentRequest);

        verify(eventService)
                .ingestEvent(eventRequest);

        verify(eventIngestionMapper)
                .toIngestionResponse(eventResponse);
    }
}
