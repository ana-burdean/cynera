package com.cynera.backend.agent.dto;

public record AgentRegistrationRequest(
        String agentName,
        String hostname
) {
}