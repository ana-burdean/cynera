package com.cynera.backend.telemetry.file.dto;

import jakarta.validation.constraints.NotBlank;
import java.time.Instant;

public record FileTelemetry(
        @NotBlank String hostname,
        @NotBlank String filePath,
        @NotBlank String fileAction,
        Long fileSize,
        String fileHash,
        String username,
        String processName,
        String parentProcessName,
        Instant timestamp
) {
}