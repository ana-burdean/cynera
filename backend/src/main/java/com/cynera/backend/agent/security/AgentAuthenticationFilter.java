package com.cynera.backend.agent.security;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.service.AgentService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AgentAuthenticationFilter extends OncePerRequestFilter {

    private static final String AGENT_TOKEN_HEADER = "X-Agent-Token";

    private final AgentService agentService;

    public AgentAuthenticationFilter(
            AgentService agentService
    ) {
        this.agentService = agentService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String agentToken =
                request.getHeader(AGENT_TOKEN_HEADER);

        if (agentToken == null
                || agentToken.isBlank()) {

            filterChain.doFilter(request, response);
            return;
        }

        try {
            Agent agent =
                    agentService.findByToken(agentToken);

            if (agent.isEnabled()
                    && SecurityContextHolder
                    .getContext()
                    .getAuthentication() == null) {

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                agent.getAgentName(),
                                null,
                                java.util.List.of(
                                        new org.springframework.security.core.authority.SimpleGrantedAuthority(
                                                "AGENT"
                                        )
                                )
                        );

                SecurityContextHolder
                        .getContext()
                        .setAuthentication(authentication);
            }
        } catch (Exception ignored) {
            // Invalid agent token: continue without authentication.
        }

        filterChain.doFilter(request, response);
    }
}