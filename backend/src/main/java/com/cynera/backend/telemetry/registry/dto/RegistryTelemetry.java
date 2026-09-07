package com.cynera.backend.telemetry.registry.dto;

import jakarta.validation.constraints.NotBlank;

import java.time.Instant;

public record RegistryTelemetry(
        @NotBlank String hostname,
        @NotBlank String registryPath,
        @NotBlank String registryAction,
        String registryValueName,
        String registryValueData,
        String username,
        String processName,
        String parentProcessName,
        Instant timestamp
) {
}
