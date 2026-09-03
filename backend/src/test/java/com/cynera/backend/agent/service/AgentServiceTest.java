package com.cynera.backend.agent.service;

import com.cynera.backend.agent.dto.AgentRegistrationRequest;
import com.cynera.backend.agent.dto.AgentResponse;
import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.repository.AgentRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AgentServiceTest {

    @Mock
    private AgentRepository agentRepository;

    @InjectMocks
    private AgentService agentService;

    @Test
    void shouldRegisterAgent() {
        AgentRegistrationRequest request =
                new AgentRegistrationRequest(
                        "agent-01",
                        "HOST-01"
                );

        Agent savedAgent = new Agent(
                "agent-01",
                "HOST-01",
                "generated-token",
                true,
                Instant.now()
        );

        when(agentRepository.existsByAgentName("agent-01"))
                .thenReturn(false);

        when(agentRepository.save(any(Agent.class)))
                .thenReturn(savedAgent);

        AgentResponse response =
                agentService.registerAgent(request);

        assertEquals(
                "agent-01",
                response.agentName()
        );

        assertEquals(
                "HOST-01",
                response.hostname()
        );

        assertTrue(response.enabled());
        assertNotNull(response.registeredAt());

        verify(agentRepository)
                .save(any(Agent.class));
    }

    @Test
    void shouldRejectDuplicateAgentName() {
        AgentRegistrationRequest request =
                new AgentRegistrationRequest(
                        "agent-01",
                        "HOST-01"
                );

        when(agentRepository.existsByAgentName("agent-01"))
                .thenReturn(true);

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> agentService.registerAgent(request)
                );

        assertTrue(
                exception.getMessage()
                        .contains("Agent name already exists")
        );

        verify(agentRepository, never())
                .save(any(Agent.class));
    }

    @Test
    void shouldFindAgentByToken() {
        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token-123",
                true,
                Instant.now()
        );

        when(agentRepository.findByAgentToken(
                "agent-token-123"
        )).thenReturn(Optional.of(agent));

        Agent result =
                agentService.findByToken("agent-token-123");

        assertEquals(
                "agent-01",
                result.getAgentName()
        );

        assertEquals(
                "agent-token-123",
                result.getAgentToken()
        );
    }

    @Test
    void shouldThrowWhenAgentTokenDoesNotExist() {
        when(agentRepository.findByAgentToken(
                "invalid-token"
        )).thenReturn(Optional.empty());

        assertThrows(
                IllegalArgumentException.class,
                () -> agentService.findByToken("invalid-token")
        );
    }
}
