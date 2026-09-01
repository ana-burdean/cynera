package com.cynera.backend.event.dto;

import com.cynera.backend.event.entity.SecurityEvent;

import java.time.Instant;

public record EventResponse(
        Long id,
        Instant timestamp,
        String eventType,
        String hostname,
        String username,
        String processName,
        String parentProcessName
) {

    public static EventResponse from(SecurityEvent event) {
        return new EventResponse(
                event.getId(),
                event.getTimestamp(),
                event.getEventType(),
                event.getHostname(),
                event.getUsername(),
                event.getProcessName(),
                event.getParentProcessName()
        );
    }
}