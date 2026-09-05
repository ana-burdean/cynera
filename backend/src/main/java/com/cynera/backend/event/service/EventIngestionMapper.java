package com.cynera.backend.event.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.event.dto.EventRequest;
import com.cynera.backend.event.dto.EventResponse;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class EventIngestionMapper {

    public EventRequest toEventRequest(
            AgentEventRequest request
    ) {
        Instant timestamp = request.timestamp() != null
                ? request.timestamp()
                : Instant.now();

        return new EventRequest(
                timestamp,
                request.eventType(),
                request.hostname(),
                request.username(),
                request.processName(),
                request.parentProcessName()
        );
    }

    public EventIngestionResponse toIngestionResponse(
            EventResponse response
    ) {
        return new EventIngestionResponse(
                response.id(),
                response.eventType(),
                response.hostname(),
                response.timestamp()
        );
    }
}