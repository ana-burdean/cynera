package com.cynera.backend.agent.service;

import com.cynera.backend.agent.dto.AgentRegistrationRequest;
import com.cynera.backend.agent.dto.AgentResponse;
import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.repository.AgentRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class AgentService {

    private final AgentRepository agentRepository;

    public AgentService(AgentRepository agentRepository) {
        this.agentRepository = agentRepository;
    }

    public AgentResponse registerAgent(
            AgentRegistrationRequest request
    ) {
        if (agentRepository.existsByAgentName(
                request.agentName()
        )) {
            throw new IllegalArgumentException(
                    "Agent name already exists: "
                            + request.agentName()
            );
        }

        String agentToken = UUID.randomUUID().toString();

        Agent agent = new Agent(
                request.agentName(),
                request.hostname(),
                agentToken,
                true,
                Instant.now()
        );

        Agent savedAgent = agentRepository.save(agent);

        return AgentResponse.from(savedAgent);
    }

    public Agent findByToken(String agentToken) {
        return agentRepository.findByAgentToken(agentToken)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Agent not found"
                ));
    }
}