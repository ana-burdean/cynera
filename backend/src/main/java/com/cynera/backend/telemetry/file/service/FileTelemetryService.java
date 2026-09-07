package com.cynera.backend.telemetry.file.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.agent.dto.FileTelemetry;
import com.cynera.backend.event.dto.EventIngestionResponse;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
public class FileTelemetryService {

    private final AgentEventService agentEventService;

    public FileTelemetryService(AgentEventService agentEventService) {
        this.agentEventService = agentEventService;
    }

    public EventIngestionResponse ingest(
            String agentToken,
            FileTelemetry telemetry
    ) {
        String eventType = resolveEventType(telemetry.fileAction());

        AgentEventRequest request = new AgentEventRequest(
                eventType,
                telemetry.hostname(),
                telemetry.username(),
                telemetry.processName(),
                telemetry.parentProcessName(),
                telemetry.timestamp(),
                telemetry.filePath(),
                telemetry.fileAction(),
                telemetry.fileSize(),
                telemetry.fileHash()
        );

        return agentEventService.ingest(agentToken, request);
    }

    private String resolveEventType(String fileAction) {
        if (fileAction == null) {
            throw new IllegalArgumentException("File action is required");
        }

        return switch (fileAction.toUpperCase(Locale.ROOT)) {
            case "CREATED" -> "FILE_CREATED";
            case "MODIFIED" -> "FILE_MODIFIED";
            case "DELETED" -> "FILE_DELETED";
            case "RENAMED" -> "FILE_RENAMED";
            default -> throw new IllegalArgumentException(
                    "Unsupported file action: " + fileAction
            );
        };
    }
}