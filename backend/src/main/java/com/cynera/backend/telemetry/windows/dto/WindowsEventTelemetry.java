package com.cynera.backend.telemetry.windows.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record WindowsEventTelemetry(
        @NotBlank String hostname,
        @NotBlank String channel,
        @NotNull Integer eventId,
        @NotBlank String provider,
        String message,
        String username,
        String processName,
        String parentProcessName,
        Instant timestamp
) {
}
