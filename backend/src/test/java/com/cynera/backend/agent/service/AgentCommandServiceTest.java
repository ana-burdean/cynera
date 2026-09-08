package com.cynera.backend.agent.service;

import com.cynera.backend.agent.dto.AgentCommand;
import com.cynera.backend.agent.dto.AgentCommandResponse;
import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.entity.AgentCommandEntity;
import com.cynera.backend.agent.repository.AgentCommandRepository;
import com.cynera.backend.agent.repository.AgentRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AgentCommandServiceTest {

    @Mock
    private AgentCommandRepository commandRepository;

    @Mock
    private AgentRepository agentRepository;

    @InjectMocks
    private AgentCommandService commandService;

    private Agent agent;
    private String agentToken = "test-token";

    @BeforeEach
    void setUp() {
        agent = new Agent("TestAgent", "WIN-HOST", agentToken, true, Instant.now());
        setId(agent, 1L);
    }

    private void setId(Agent agent, Long id) {
        try {
            java.lang.reflect.Field field = Agent.class.getDeclaredField("id");
            field.setAccessible(true);
            field.set(agent, id);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void shouldQueueCommand() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));
        when(commandRepository.save(any(AgentCommandEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        AgentCommand command = AgentCommand.killProcess("1234", "malware.exe", "corr-1");
        AgentCommandEntity result = commandService.queueCommand(agentToken, command);

        assertEquals(command.commandId(), result.getCommandId());
        assertEquals("KILL_PROCESS", result.getCommandType());
        assertEquals(agent, result.getAgent());
        assertEquals(AgentCommandEntity.Status.PENDING, result.getStatus());

        verify(commandRepository).save(any(AgentCommandEntity.class));
    }

    @Test
    void shouldThrowWhenAgentNotFoundOnQueue() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.empty());

        AgentCommand command = AgentCommand.killProcess("1234", "malware.exe", "corr-1");
        assertThrows(IllegalArgumentException.class, () -> commandService.queueCommand(agentToken, command));
    }

    @Test
    void shouldGetPendingCommands() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));

        AgentCommandEntity cmd1 = new AgentCommandEntity("cmd-1", agent, "KILL_PROCESS", Map.of(), "corr-1", Instant.now());
        AgentCommandEntity cmd2 = new AgentCommandEntity("cmd-2", agent, "QUARANTINE_FILE", Map.of(), "corr-2", Instant.now().plusSeconds(1));

        when(commandRepository.findByAgentAndStatusOrderByCreatedAtAsc(agent, AgentCommandEntity.Status.PENDING))
                .thenReturn(List.of(cmd1, cmd2));

        List<AgentCommand> commands = commandService.getPendingCommands(agentToken);

        assertEquals(2, commands.size());
        assertEquals("cmd-1", commands.get(0).commandId());
        assertEquals("KILL_PROCESS", commands.get(0).commandType());
        assertEquals("cmd-2", commands.get(1).commandId());
        assertEquals("QUARANTINE_FILE", commands.get(1).commandType());
    }

    @Test
    void shouldHandleCommandResultSuccess() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));

        AgentCommandEntity entity = new AgentCommandEntity("cmd-1", agent, "KILL_PROCESS", Map.of(), "corr-1", Instant.now());
        when(commandRepository.findByCommandIdAndAgent("cmd-1", agent)).thenReturn(Optional.of(entity));
        when(commandRepository.save(any(AgentCommandEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        AgentCommandResponse response = AgentCommandResponse.success("cmd-1", "KILL_PROCESS", "Killed", Map.of());
        commandService.handleCommandResult(agentToken, "cmd-1", response);

        assertEquals(AgentCommandEntity.Status.COMPLETED, entity.getStatus());
        assertEquals("Killed", entity.getResultMessage());
        assertNotNull(entity.getExecutedAt());
        assertNotNull(entity.getCompletedAt());

        verify(commandRepository).save(entity);
    }

    @Test
    void shouldHandleCommandResultFailure() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));

        AgentCommandEntity entity = new AgentCommandEntity("cmd-1", agent, "KILL_PROCESS", Map.of(), "corr-1", Instant.now());
        when(commandRepository.findByCommandIdAndAgent("cmd-1", agent)).thenReturn(Optional.of(entity));
        when(commandRepository.save(any(AgentCommandEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        AgentCommandResponse response = AgentCommandResponse.failure("cmd-1", "KILL_PROCESS", "Process not found");
        commandService.handleCommandResult(agentToken, "cmd-1", response);

        assertEquals(AgentCommandEntity.Status.FAILED, entity.getStatus());
        assertEquals("Process not found", entity.getResultMessage());
    }

    @Test
    void shouldThrowWhenCommandNotFound() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));
        when(commandRepository.findByCommandIdAndAgent("cmd-999", agent)).thenReturn(Optional.empty());

        AgentCommandResponse response = AgentCommandResponse.success("cmd-999", "KILL_PROCESS", "OK", Map.of());
        assertThrows(IllegalArgumentException.class, () -> commandService.handleCommandResult(agentToken, "cmd-999", response));
    }

    @Test
    void shouldSendKillProcessCommand() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));
        when(commandRepository.save(any(AgentCommandEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        AgentCommandEntity result = commandService.sendKillProcessCommand(agentToken, "1234", "malware.exe", "corr-1");

        assertEquals("KILL_PROCESS", result.getCommandType());
        assertEquals("1234", result.getParameters().get("processId"));
        assertEquals("malware.exe", result.getParameters().get("processName"));
        assertEquals("corr-1", result.getCorrelationId());
    }

    @Test
    void shouldSendQuarantineFileCommand() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));
        when(commandRepository.save(any(AgentCommandEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        AgentCommandEntity result = commandService.sendQuarantineFileCommand(agentToken, "C:\\bad.exe", "Ransomware", "corr-2");

        assertEquals("QUARANTINE_FILE", result.getCommandType());
        assertEquals("C:\\bad.exe", result.getParameters().get("filePath"));
        assertEquals("Ransomware", result.getParameters().get("reason"));
    }

    @Test
    void shouldSendIsolateEndpointCommand() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));
        when(commandRepository.save(any(AgentCommandEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        AgentCommandEntity result = commandService.sendIsolateEndpointCommand(agentToken, "WIN-HOST", "Critical threat", "corr-3");

        assertEquals("ISOLATE_ENDPOINT", result.getCommandType());
        assertEquals("WIN-HOST", result.getParameters().get("hostname"));
        assertEquals("Critical threat", result.getParameters().get("reason"));
    }

    @Test
    void shouldSendProtectFileCommand() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));
        when(commandRepository.save(any(AgentCommandEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        AgentCommandEntity result = commandService.sendProtectFileCommand(agentToken, "C:\\critical.dll", "corr-4");

        assertEquals("PROTECT_FILE", result.getCommandType());
        assertEquals("C:\\critical.dll", result.getParameters().get("filePath"));
    }

    @Test
    void shouldSendUnprotectFileCommand() {
        when(agentRepository.findByAgentToken(agentToken)).thenReturn(Optional.of(agent));
        when(commandRepository.save(any(AgentCommandEntity.class))).thenAnswer(inv -> inv.getArgument(0));

        AgentCommandEntity result = commandService.sendUnprotectFileCommand(agentToken, "C:\\temp.txt", "corr-5");

        assertEquals("UNPROTECT_FILE", result.getCommandType());
        assertEquals("C:\\temp.txt", result.getParameters().get("filePath"));
    }
}