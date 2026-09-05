package com.cynera.backend.agent.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.event.service.EventIngestionService;
import org.springframework.stereotype.Service;

@Service
public class AgentEventService {

    private final AgentService agentService;
    private final AgentEventValidationService validationService;
    private final EventIngestionService eventIngestionService;

    public AgentEventService(
            AgentService agentService,
            AgentEventValidationService validationService,
            EventIngestionService eventIngestionService
    ) {
        this.agentService = agentService;
        this.validationService = validationService;
        this.eventIngestionService = eventIngestionService;
    }

    public EventIngestionResponse ingest(
            String agentToken,
            AgentEventRequest request
    ) {
        Agent agent = agentService.findByToken(agentToken);

        if (!agent.isEnabled()) {
            throw new IllegalArgumentException(
                    "Agent is disabled"
            );
        }

        validationService.validateAgentHostname(
                agent,
                request.hostname()
        );

        return eventIngestionService.ingest(request);
    }
}