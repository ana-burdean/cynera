package com.cynera.backend.agent.controller;

import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.windows.dto.WindowsEventTelemetry;
import com.cynera.backend.telemetry.windows.service.WindowsEventTelemetryService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/agent/windows-events")
public class AgentWindowsEventController {

    private final WindowsEventTelemetryService windowsEventTelemetryService;

    public AgentWindowsEventController(WindowsEventTelemetryService windowsEventTelemetryService) {
        this.windowsEventTelemetryService = windowsEventTelemetryService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public EventIngestionResponse ingestWindowsEvent(
            @RequestHeader("X-Agent-Token") String agentToken,
            @Valid @RequestBody WindowsEventTelemetry telemetry
    ) {
        return windowsEventTelemetryService.ingest(agentToken, telemetry);
    }
}
