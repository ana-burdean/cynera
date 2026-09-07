package com.cynera.backend.telemetry.windows.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.telemetry.windows.dto.WindowsEventTelemetry;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class WindowsEventTelemetryServiceTest {

    private final AgentEventService agentEventService = mock(AgentEventService.class);
    private final WindowsEventTelemetryService windowsEventTelemetryService =
            new WindowsEventTelemetryService(agentEventService);

    @Test
    void shouldMapWindowsEvent() {
        WindowsEventTelemetry telemetry = new WindowsEventTelemetry(
                "WIN-EVT-01", "Security", 4625, "Microsoft-Windows-Security-Auditing",
                "An account failed to log on", "ana", null, null,
                Instant.parse("2026-09-07T12:00:00Z"));
        when(agentEventService.ingest(eq("token"), any(AgentEventRequest.class)))
                .thenReturn(null);

        windowsEventTelemetryService.ingest("token", telemetry);

        ArgumentCaptor<AgentEventRequest> captor =
                ArgumentCaptor.forClass(AgentEventRequest.class);
        verify(agentEventService).ingest(eq("token"), captor.capture());
        AgentEventRequest request = captor.getValue();
        assertEquals("WINDOWS_EVENT", request.eventType());
        assertEquals("Security", request.windowsEventChannel());
        assertEquals(4625, request.windowsEventId());
        assertEquals("Microsoft-Windows-Security-Auditing", request.windowsEventProvider());
        assertEquals("An account failed to log on", request.windowsEventMessage());
    }

    @Test
    void shouldRejectNullTelemetry() {
        assertThrows(IllegalArgumentException.class,
                () -> windowsEventTelemetryService.ingest("token", null));
    }
}
