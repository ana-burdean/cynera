package com.cynera.backend.telemetry.registry.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.registry.dto.RegistryTelemetry;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Locale;

@Service
public class RegistryTelemetryService {

    private final AgentEventService agentEventService;

    public RegistryTelemetryService(AgentEventService agentEventService) {
        this.agentEventService = agentEventService;
    }

    public EventIngestionResponse ingest(String agentToken, RegistryTelemetry telemetry) {
        if (telemetry == null) {
            throw new IllegalArgumentException("Registry telemetry is required");
        }

        String eventType = switch (telemetry.registryAction().toUpperCase(Locale.ROOT)) {
            case "CREATED" -> "REGISTRY_CREATED";
            case "MODIFIED" -> "REGISTRY_MODIFIED";
            case "DELETED" -> "REGISTRY_DELETED";
            default -> throw new IllegalArgumentException(
                    "Unsupported registry action: " + telemetry.registryAction());
        };

        AgentEventRequest request = new AgentEventRequest(
                eventType, telemetry.hostname(), telemetry.username(),
                telemetry.processName(), telemetry.parentProcessName(),
                telemetry.timestamp() != null ? telemetry.timestamp() : Instant.now(),
                null, null, null, null, null, null, null,
                telemetry.registryPath(), telemetry.registryAction(),
                telemetry.registryValueName(), telemetry.registryValueData()
        );

        return agentEventService.ingest(agentToken, request);
    }
}
