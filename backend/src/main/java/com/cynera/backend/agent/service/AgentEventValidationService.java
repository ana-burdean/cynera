package com.cynera.backend.agent.service;

import com.cynera.backend.agent.entity.Agent;
import org.springframework.stereotype.Service;

@Service
public class AgentEventValidationService {

    public void validateAgentHostname(
            Agent agent,
            String hostname
    ) {
        if (!agent.getHostname().equals(hostname)) {
            throw new IllegalArgumentException(
                    "Agent hostname does not match registered hostname"
            );
        }
    }
}