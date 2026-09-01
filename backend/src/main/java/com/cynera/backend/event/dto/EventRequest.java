package com.cynera.backend.event.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record EventRequest(

        @NotNull(message = "timestamp is required")
        Instant timestamp,

        @NotBlank(message = "eventType is required")
        String eventType,

        @NotBlank(message = "hostname is required")
        String hostname,

        String username,

        String processName,

        String parentProcessName
) {
}