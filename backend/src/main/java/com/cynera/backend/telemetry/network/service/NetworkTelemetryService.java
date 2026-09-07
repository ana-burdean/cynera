package com.cynera.backend.telemetry.network.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.network.dto.NetworkTelemetry;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class NetworkTelemetryService {

    private final AgentEventService agentEventService;

    public NetworkTelemetryService(AgentEventService agentEventService) {
        this.agentEventService = agentEventService;
    }

    public EventIngestionResponse ingest(
            String agentToken,
            NetworkTelemetry telemetry
    ) {
        if (telemetry == null) {
            throw new IllegalArgumentException("Network telemetry is required");
        }

        if (telemetry.remoteAddress() == null
                || telemetry.remoteAddress().isBlank()) {
            throw new IllegalArgumentException("Remote address is required");
        }

        Instant timestamp = telemetry.timestamp() != null
                ? telemetry.timestamp()
                : Instant.now();

        AgentEventRequest request = new AgentEventRequest(
                "NETWORK_CONNECTION",
                telemetry.hostname(),
                telemetry.username(),
                telemetry.processName(),
                telemetry.parentProcessName(),
                timestamp,
                null,
                null,
                null,
                null,
                telemetry.remoteAddress(),
                telemetry.remotePort(),
                telemetry.protocol()
        );

        return agentEventService.ingest(agentToken, request);
    }
}
