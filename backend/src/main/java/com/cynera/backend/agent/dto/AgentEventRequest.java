package com.cynera.backend.agent.dto;

import jakarta.validation.constraints.NotBlank;

import java.time.Instant;

public record AgentEventRequest(
        @NotBlank
        String eventType,

        @NotBlank
        String hostname,

        String username,

        String processName,

        String parentProcessName,

        Instant timestamp
) {
}