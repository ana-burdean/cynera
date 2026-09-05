package com.cynera.backend.event.dto;

import java.time.Instant;

public record EventIngestionResponse(
        Long eventId,
        String eventType,
        String hostname,
        Instant timestamp
) {
}