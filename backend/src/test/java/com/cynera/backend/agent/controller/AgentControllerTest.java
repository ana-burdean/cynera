package com.cynera.backend.agent.controller;

import com.cynera.backend.agent.dto.AgentRegistrationRequest;
import com.cynera.backend.agent.dto.AgentResponse;
import com.cynera.backend.agent.service.AgentService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AgentControllerTest {

    @Mock
    private AgentService agentService;

    @InjectMocks
    private AgentController agentController;

    @Test
    void registerAgentShouldReturnCreatedResponse() {

        AgentRegistrationRequest request =
                new AgentRegistrationRequest(
                        "agent-01",
                        "HOST-01"
                );

        AgentResponse agentResponse =
                new AgentResponse(
                        1L,
                        "agent-01",
                        "HOST-01",
                        "agent-token",
                        true,
                        Instant.now()
                );

        when(agentService.registerAgent(request))
                .thenReturn(agentResponse);

        var response =
                agentController.registerAgent(request);

        assertEquals(
                HttpStatus.CREATED,
                response.getStatusCode()
        );

        assertNotNull(response.getBody());

        assertEquals(
                "agent-01",
                response.getBody().agentName()
        );

        assertEquals(
                "HOST-01",
                response.getBody().hostname()
        );

        assertEquals(
                "agent-token",
                response.getBody().agentToken()
        );

        verify(agentService)
                .registerAgent(request);
    }
}