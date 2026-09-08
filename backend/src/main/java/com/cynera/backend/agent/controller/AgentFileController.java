package com.cynera.backend.agent.controller;

import com.cynera.backend.telemetry.file.dto.FileTelemetry;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.file.service.FileTelemetryService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/agent/files")
public class AgentFileController {

    private final FileTelemetryService fileTelemetryService;

    public AgentFileController(FileTelemetryService fileTelemetryService) {
        this.fileTelemetryService = fileTelemetryService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public EventIngestionResponse ingestFile(
            @RequestHeader("X-Agent-Token") String agentToken,
            @Valid @RequestBody FileTelemetry telemetry
    ) {
        return fileTelemetryService.ingest(agentToken, telemetry);
    }
}