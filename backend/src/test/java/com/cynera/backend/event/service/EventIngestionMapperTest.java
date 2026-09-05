package com.cynera.backend.event.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.event.dto.EventRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class EventIngestionMapperTest {

    private final EventIngestionMapper mapper =
            new EventIngestionMapper();

    @Test
    void shouldMapAgentEventRequestToEventRequest() {

        Instant timestamp =
                Instant.parse("2026-09-04T07:00:00Z");

        AgentEventRequest request =
                new AgentEventRequest(
                        "PROCESS_START",
                        "HOST-01",
                        "alice",
                        "powershell.exe",
                        "explorer.exe",
                        timestamp
                );

        EventRequest result =
                mapper.toEventRequest(request);

        assertEquals(timestamp, result.timestamp());
        assertEquals(
                "PROCESS_START",
                result.eventType()
        );
        assertEquals(
                "HOST-01",
                result.hostname()
        );
        assertEquals(
                "alice",
                result.username()
        );
        assertEquals(
                "powershell.exe",
                result.processName()
        );
        assertEquals(
                "explorer.exe",
                result.parentProcessName()
        );
    }

    @Test
    void shouldGenerateTimestampWhenMissing() {

        AgentEventRequest request =
                new AgentEventRequest(
                        "PROCESS_START",
                        "HOST-01",
                        "alice",
                        "powershell.exe",
                        "explorer.exe",
                        null
                );

        Instant before = Instant.now();

        EventRequest result =
                mapper.toEventRequest(request);

        Instant after = Instant.now();

        assertNotNull(result.timestamp());

        assertFalse(
                result.timestamp().isBefore(before)
        );

        assertFalse(
                result.timestamp().isAfter(after)
        );
    }
}
