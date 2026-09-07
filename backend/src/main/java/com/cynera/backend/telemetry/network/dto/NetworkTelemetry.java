package com.cynera.backend.telemetry.network.dto;

import jakarta.validation.constraints.NotBlank;

import java.time.Instant;

public record NetworkTelemetry(
        @NotBlank String hostname,
        @NotBlank String remoteAddress,
        Integer remotePort,
        String protocol,
        String username,
        String processName,
        String parentProcessName,
        Instant timestamp
) {
}