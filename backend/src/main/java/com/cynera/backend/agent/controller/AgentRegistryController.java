package com.cynera.backend.agent.controller;

import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.registry.dto.RegistryTelemetry;
import com.cynera.backend.telemetry.registry.service.RegistryTelemetryService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/agent/registry")
public class AgentRegistryController {

    private final RegistryTelemetryService registryTelemetryService;

    public AgentRegistryController(RegistryTelemetryService registryTelemetryService) {
        this.registryTelemetryService = registryTelemetryService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public EventIngestionResponse ingestRegistry(
            @RequestHeader("X-Agent-Token") String agentToken,
            @Valid @RequestBody RegistryTelemetry telemetry
    ) {
        return registryTelemetryService.ingest(agentToken, telemetry);
    }
}
