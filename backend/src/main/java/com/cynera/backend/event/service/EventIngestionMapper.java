package com.cynera.backend.event.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.event.dto.EventRequest;
import com.cynera.backend.event.dto.EventResponse;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class EventIngestionMapper {

    public EventRequest toEventRequest(AgentEventRequest request) {

        Instant timestamp = request.timestamp() != null
                ? request.timestamp()
                : Instant.now();

        return new EventRequest(
                timestamp,
                request.eventType(),
                request.hostname(),
                request.username(),
                request.processName(),
                request.parentProcessName(),
                request.filePath(),
                request.fileAction(),
                request.fileSize(),
                request.fileHash(),
                request.remoteAddress(),
                request.remotePort(),
                request.networkProtocol(),
                request.registryPath(),
                request.registryAction(),
                request.registryValueName(),
                request.registryValueData(),
                request.windowsEventChannel(),
                request.windowsEventId(),
                request.windowsEventProvider(),
                request.windowsEventMessage()
        );
    }

    public EventIngestionResponse toIngestionResponse(EventResponse response) {

        return new EventIngestionResponse(
                response.id(),
                response.eventType(),
                response.hostname(),
                response.timestamp()
        );
    }
}
