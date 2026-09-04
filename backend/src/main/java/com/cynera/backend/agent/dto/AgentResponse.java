package com.cynera.backend.agent.dto;

import com.cynera.backend.agent.entity.Agent;

import java.time.Instant;

public record AgentResponse(
        Long id,
        String agentName,
        String hostname,
        String agentToken,
        boolean enabled,
        Instant registeredAt
) {

    public static AgentResponse from(Agent agent) {
        return new AgentResponse(
                agent.getId(),
                agent.getAgentName(),
                agent.getHostname(),
                agent.getAgentToken(),
                agent.isEnabled(),
                agent.getRegisteredAt()
        );
    }
}