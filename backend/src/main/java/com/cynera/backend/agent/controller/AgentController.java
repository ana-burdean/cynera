package com.cynera.backend.agent.controller;

import com.cynera.backend.agent.dto.AgentRegistrationRequest;
import com.cynera.backend.agent.dto.AgentResponse;
import com.cynera.backend.agent.service.AgentService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/agents")
public class AgentController {

    private final AgentService agentService;

    public AgentController(AgentService agentService) {
        this.agentService = agentService;
    }

    @PostMapping("/register")
    public ResponseEntity<AgentResponse> registerAgent(
            @RequestBody AgentRegistrationRequest request
    ) {
        AgentResponse response =
                agentService.registerAgent(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }
}