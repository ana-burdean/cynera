package com.cynera.backend.agent.service;

import com.cynera.backend.agent.dto.AgentCommand;
import com.cynera.backend.agent.dto.AgentCommandResponse;
import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.entity.AgentCommandEntity;
import com.cynera.backend.agent.repository.AgentCommandRepository;
import com.cynera.backend.agent.repository.AgentRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class AgentCommandService {

    private final AgentCommandRepository commandRepository;
    private final AgentRepository agentRepository;

    public AgentCommandService(AgentCommandRepository commandRepository, AgentRepository agentRepository) {
        this.commandRepository = commandRepository;
        this.agentRepository = agentRepository;
    }

    @Transactional
    public AgentCommandEntity queueCommand(String agentToken, AgentCommand command) {
        Agent agent = agentRepository.findByAgentToken(agentToken)
                .orElseThrow(() -> new IllegalArgumentException("Agent not found"));

        AgentCommandEntity entity = new AgentCommandEntity(
                command.commandId(),
                agent,
                command.commandType(),
                command.parameters(),
                command.correlationId(),
                Instant.now()
        );

        return commandRepository.save(entity);
    }

    @Transactional(readOnly = true)
    public List<AgentCommand> getPendingCommands(String agentToken) {
        Agent agent = agentRepository.findByAgentToken(agentToken)
                .orElseThrow(() -> new IllegalArgumentException("Agent not found"));

        return commandRepository.findByAgentAndStatusOrderByCreatedAtAsc(agent, AgentCommandEntity.Status.PENDING)
                .stream()
                .map(this::toDto)
                .collect(Collectors.toList());
    }

    @Transactional
    public void handleCommandResult(String agentToken, String commandId, AgentCommandResponse response) {
        Agent agent = agentRepository.findByAgentToken(agentToken)
                .orElseThrow(() -> new IllegalArgumentException("Agent not found"));

        AgentCommandEntity entity = commandRepository.findByCommandIdAndAgent(commandId, agent)
                .orElseThrow(() -> new IllegalArgumentException("Command not found: " + commandId));

        entity.setStatus(response.success() ? AgentCommandEntity.Status.COMPLETED : AgentCommandEntity.Status.FAILED);
        entity.setResultMessage(response.message());
        entity.setResultDetails(response.details());
        entity.setExecutedAt(response.executedAt());
        entity.setCompletedAt(Instant.now());

        commandRepository.save(entity);
    }

    @Transactional
    public AgentCommandEntity sendKillProcessCommand(String agentToken, String processId, String processName, String correlationId) {
        AgentCommand command = AgentCommand.killProcess(processId, processName, correlationId);
        return queueCommand(agentToken, command);
    }

    @Transactional
    public AgentCommandEntity sendQuarantineFileCommand(String agentToken, String filePath, String reason, String correlationId) {
        AgentCommand command = AgentCommand.quarantineFile(filePath, reason, correlationId);
        return queueCommand(agentToken, command);
    }

    @Transactional
    public AgentCommandEntity sendIsolateEndpointCommand(String agentToken, String hostname, String reason, String correlationId) {
        AgentCommand command = AgentCommand.isolateEndpoint(hostname, reason, correlationId);
        return queueCommand(agentToken, command);
    }

    @Transactional
    public AgentCommandEntity sendProtectFileCommand(String agentToken, String filePath, String correlationId) {
        AgentCommand command = AgentCommand.protectFile(filePath, correlationId);
        return queueCommand(agentToken, command);
    }

    @Transactional
    public AgentCommandEntity sendUnprotectFileCommand(String agentToken, String filePath, String correlationId) {
        AgentCommand command = AgentCommand.unprotectFile(filePath, correlationId);
        return queueCommand(agentToken, command);
    }

    private AgentCommand toDto(AgentCommandEntity entity) {
        return new AgentCommand(
                entity.getCommandId(),
                entity.getCommandType(),
                entity.getCreatedAt(),
                entity.getParameters(),
                entity.getCorrelationId()
        );
    }
}