package com.cynera.backend.agent.dto;

import java.time.Instant;
import java.util.Map;

public record AgentCommandResponse(
        String commandId,
        String commandType,
        boolean success,
        String message,
        Map<String, Object> details,
        Instant executedAt
) {
    public static AgentCommandResponse success(String commandId, String commandType, String message, Map<String, Object> details) {
        return new AgentCommandResponse(commandId, commandType, true, message, details, Instant.now());
    }

    public static AgentCommandResponse failure(String commandId, String commandType, String message) {
        return new AgentCommandResponse(commandId, commandType, false, message, Map.of(), Instant.now());
    }
}