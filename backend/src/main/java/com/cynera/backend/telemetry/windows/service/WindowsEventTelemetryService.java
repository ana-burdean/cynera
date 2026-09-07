package com.cynera.backend.telemetry.windows.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.windows.dto.WindowsEventTelemetry;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class WindowsEventTelemetryService {

    private final AgentEventService agentEventService;

    public WindowsEventTelemetryService(AgentEventService agentEventService) {
        this.agentEventService = agentEventService;
    }

    public EventIngestionResponse ingest(String agentToken, WindowsEventTelemetry telemetry) {
        if (telemetry == null) {
            throw new IllegalArgumentException("Windows event telemetry is required");
        }

        AgentEventRequest request = new AgentEventRequest(
                "WINDOWS_EVENT", telemetry.hostname(), telemetry.username(),
                telemetry.processName(), telemetry.parentProcessName(),
                telemetry.timestamp() != null ? telemetry.timestamp() : Instant.now(),
                null, null, null, null, null, null, null, null, null, null, null,
                telemetry.channel(), telemetry.eventId(), telemetry.provider(), telemetry.message()
        );
        return agentEventService.ingest(agentToken, request);
    }
}
