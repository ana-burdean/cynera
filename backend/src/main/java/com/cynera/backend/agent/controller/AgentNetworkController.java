package com.cynera.backend.agent.controller;

import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.network.dto.NetworkTelemetry;
import com.cynera.backend.telemetry.network.service.NetworkTelemetryService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/agent/network")
public class AgentNetworkController {

    private final NetworkTelemetryService networkTelemetryService;

    public AgentNetworkController(
            NetworkTelemetryService networkTelemetryService
    ) {
        this.networkTelemetryService = networkTelemetryService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public EventIngestionResponse ingestNetwork(
            @RequestHeader("X-Agent-Token") String agentToken,
            @Valid @RequestBody NetworkTelemetry telemetry
    ) {
        return networkTelemetryService.ingest(
                agentToken,
                telemetry
        );
    }
}