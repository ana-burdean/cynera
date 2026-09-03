package com.cynera.backend.agent.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class AgentTest {

    @Test
    void shouldCreateEnabledAgent() {
        Instant registeredAt = Instant.now();

        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token-123",
                true,
                registeredAt
        );

        assertEquals(
                "agent-01",
                agent.getAgentName()
        );

        assertEquals(
                "HOST-01",
                agent.getHostname()
        );

        assertEquals(
                "agent-token-123",
                agent.getAgentToken()
        );

        assertTrue(agent.isEnabled());

        assertEquals(
                registeredAt,
                agent.getRegisteredAt()
        );
    }

    @Test
    void idShouldBeNullBeforePersistence() {
        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token-123",
                true,
                Instant.now()
        );

        assertNull(agent.getId());
    }

    @Test
    void shouldCreateDisabledAgent() {
        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token-123",
                false,
                Instant.now()
        );

        assertFalse(agent.isEnabled());
    }
}
