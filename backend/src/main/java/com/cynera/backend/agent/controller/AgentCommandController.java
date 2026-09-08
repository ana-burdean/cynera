package com.cynera.backend.agent.controller;

import com.cynera.backend.agent.dto.AgentCommand;
import com.cynera.backend.agent.dto.AgentCommandResponse;
import com.cynera.backend.agent.service.AgentCommandService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/agent/commands")
public class AgentCommandController {

    private final AgentCommandService commandService;

    public AgentCommandController(AgentCommandService commandService) {
        this.commandService = commandService;
    }

    @GetMapping("/pending")
    public List<AgentCommand> getPendingCommands(
            @RequestHeader("X-Agent-Token") String agentToken
    ) {
        return commandService.getPendingCommands(agentToken);
    }

    @PostMapping("/{commandId}/result")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void reportCommandResult(
            @RequestHeader("X-Agent-Token") String agentToken,
            @PathVariable String commandId,
            @Valid @RequestBody AgentCommandResponse response
    ) {
        commandService.handleCommandResult(agentToken, commandId, response);
    }
}