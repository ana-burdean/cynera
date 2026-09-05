package com.cynera.backend.agent.service;

import com.cynera.backend.agent.entity.Agent;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AgentEventValidationServiceTest {

    private final AgentEventValidationService validationService =
            new AgentEventValidationService();

    @Test
    void shouldAcceptMatchingHostname() {

        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token",
                true,
                Instant.now()
        );

        assertDoesNotThrow(() ->
                validationService.validateAgentHostname(
                        agent,
                        "HOST-01"
                )
        );
    }

    @Test
    void shouldRejectDifferentHostname() {

        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token",
                true,
                Instant.now()
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> validationService.validateAgentHostname(
                        agent,
                        "OTHER-HOST"
                )
        );
    }
}
