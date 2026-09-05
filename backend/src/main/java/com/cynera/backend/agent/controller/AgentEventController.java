package com.cynera.backend.agent.controller;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.event.dto.EventIngestionResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/agent/events")
public class AgentEventController {

    private static final String AGENT_TOKEN_HEADER =
            "X-Agent-Token";

    private final AgentEventService agentEventService;

    public AgentEventController(
            AgentEventService agentEventService
    ) {
        this.agentEventService = agentEventService;
    }

    @PostMapping
    public ResponseEntity<EventIngestionResponse> ingestEvent(
            @RequestHeader(AGENT_TOKEN_HEADER) String agentToken,
            @Valid @RequestBody AgentEventRequest request
    ) {
        EventIngestionResponse response =
                agentEventService.ingest(
                        agentToken,
                        request
                );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }
}