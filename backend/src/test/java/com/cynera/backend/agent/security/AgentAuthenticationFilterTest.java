package com.cynera.backend.agent.security;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.service.AgentService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AgentAuthenticationFilterTest {

    @Mock
    private AgentService agentService;

    @Mock
    private FilterChain filterChain;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldContinueWithoutAuthenticationWhenHeaderIsMissing()
            throws Exception {

        AgentAuthenticationFilter filter =
                new AgentAuthenticationFilter(agentService);

        MockHttpServletRequest request =
                new MockHttpServletRequest();

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain)
                .doFilter(request, response);

        verifyNoInteractions(agentService);

        assertNull(
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
        );
    }

    @Test
    void shouldAuthenticateValidAgentToken()
            throws Exception {

        AgentAuthenticationFilter filter =
                new AgentAuthenticationFilter(agentService);

        MockHttpServletRequest request =
                new MockHttpServletRequest();

        request.addHeader(
                "X-Agent-Token",
                "agent-token"
        );

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token",
                true,
                Instant.now()
        );

        when(agentService.findByToken("agent-token"))
                .thenReturn(agent);

        SecurityContextHolder.clearContext();

        filter.doFilter(request, response, filterChain);

        assertNotNull(
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
        );

        assertEquals(
                "agent-01",
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
                        .getName()
        );

        assertTrue(
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
                        .getAuthorities()
                        .stream()
                        .anyMatch(authority ->
                                authority.getAuthority()
                                        .equals("AGENT")
                        )
        );

        verify(filterChain)
                .doFilter(request, response);
    }

    @Test
    void shouldNotAuthenticateDisabledAgent()
            throws Exception {

        AgentAuthenticationFilter filter =
                new AgentAuthenticationFilter(agentService);

        MockHttpServletRequest request =
                new MockHttpServletRequest();

        request.addHeader(
                "X-Agent-Token",
                "agent-token"
        );

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        Agent agent = new Agent(
                "agent-01",
                "HOST-01",
                "agent-token",
                false,
                Instant.now()
        );

        when(agentService.findByToken("agent-token"))
                .thenReturn(agent);

        filter.doFilter(request, response, filterChain);

        assertNull(
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
        );

        verify(filterChain)
                .doFilter(request, response);
    }

    @Test
    void shouldContinueWithoutAuthenticationForInvalidToken()
            throws Exception {

        AgentAuthenticationFilter filter =
                new AgentAuthenticationFilter(agentService);

        MockHttpServletRequest request =
                new MockHttpServletRequest();

        request.addHeader(
                "X-Agent-Token",
                "invalid-token"
        );

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        when(agentService.findByToken("invalid-token"))
                .thenThrow(new IllegalArgumentException(
                        "Agent not found"
                ));

        filter.doFilter(request, response, filterChain);

        assertNull(
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
        );

        verify(filterChain)
                .doFilter(request, response);
    }
}