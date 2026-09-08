package com.cynera.backend.agent.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record AgentCommand(
        @NotBlank String commandId,
        @NotBlank String commandType,
        @NotNull Instant timestamp,
        Map<String, Object> parameters,
        String correlationId
) {

    public static AgentCommand killProcess(String processId, String processName, String correlationId) {
        return new AgentCommand(
                UUID.randomUUID().toString(),
                "KILL_PROCESS",
                Instant.now(),
                Map.of("processId", processId, "processName", processName),
                correlationId
        );
    }

    public static AgentCommand quarantineFile(String filePath, String reason, String correlationId) {
        return new AgentCommand(
                UUID.randomUUID().toString(),
                "QUARANTINE_FILE",
                Instant.now(),
                Map.of("filePath", filePath, "reason", reason),
                correlationId
        );
    }

    public static AgentCommand isolateEndpoint(String hostname, String reason, String correlationId) {
        return new AgentCommand(
                UUID.randomUUID().toString(),
                "ISOLATE_ENDPOINT",
                Instant.now(),
                Map.of("hostname", hostname, "reason", reason),
                correlationId
        );
    }

    public static AgentCommand protectFile(String filePath, String correlationId) {
        return new AgentCommand(
                UUID.randomUUID().toString(),
                "PROTECT_FILE",
                Instant.now(),
                Map.of("filePath", filePath),
                correlationId
        );
    }

    public static AgentCommand unprotectFile(String filePath, String correlationId) {
        return new AgentCommand(
                UUID.randomUUID().toString(),
                "UNPROTECT_FILE",
                Instant.now(),
                Map.of("filePath", filePath),
                correlationId
        );
    }
}