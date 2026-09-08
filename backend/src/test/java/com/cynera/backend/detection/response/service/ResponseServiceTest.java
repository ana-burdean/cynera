package com.cynera.backend.detection.response.service;
import com.cynera.backend.detection.response.entity.ResponseAction;
import com.cynera.backend.detection.response.repository.ResponseActionRepository;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.entity.AgentCommandEntity;
import com.cynera.backend.agent.repository.AgentRepository;
import com.cynera.backend.agent.service.AgentCommandService;
import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.entity.SecurityIncident;
import com.cynera.backend.detection.model.RiskScore;
import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.detection.ransomware.ProtectedFileService;
import com.cynera.backend.detection.repository.SecurityIncidentRepository;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ResponseServiceTest {

    @Mock
    private ResponseActionRepository actionRepository;

    @Mock
    private AgentCommandService agentCommandService;

    @Mock
    private AgentRepository agentRepository;

    @Mock
    private ProtectedFileService protectedFileService;

    @Mock
    private SecurityIncidentRepository incidentRepository;

    @InjectMocks
    private ResponseService responseService;

    private Agent agent;
    private SecurityIncident incident;
    private Detection detection;

    @BeforeEach
    void setUp() {
        agent = new Agent("TestAgent", "WIN-HOST", "agent-token-123", true, Instant.now());
        setId(agent, 1L);

        incident = new SecurityIncident("WIN-HOST", "testuser", RiskScore.CRITICAL, Instant.now());
        setId(incident, 1L);

        SecurityEvent event = new SecurityEvent(
                Instant.now(), "FILE_MODIFIED", "WIN-HOST", "testuser",
                "ransomware.exe", "explorer.exe", "C:\\test.encrypted",
                "MODIFIED", 1024L, "hash", null, null, null,
                null, null, null, null, null, null, null, null
        );
        detection = new Detection(event, "RANSOMWARE_FILE_ENCRYPTION", Severity.CRITICAL, "Ransomware", Instant.now());
        setId(detection, 1L);

        lenient().when(incidentRepository.findById(1L)).thenReturn(Optional.of(incident));
    }

    private void setId(Object entity, Long id) {
        try {
            Field field = entity.getClass().getDeclaredField("id");
            field.setAccessible(true);
            field.set(entity, id);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void shouldExecuteKillProcess() {
        when(actionRepository.save(any(ResponseAction.class))).thenAnswer(inv -> inv.getArgument(0));
        when(agentRepository.findByHostname("WIN-HOST")).thenReturn(Optional.of(agent));
        when(agentCommandService.sendKillProcessCommand(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));

        ResponseAction action = responseService.executeKillProcess(1L, 1L, "1234", "malware.exe", "test-user");

        assertNotNull(action);
        assertEquals("KILL_PROCESS", action.getActionType());
        assertEquals("malware.exe", action.getTargetIdentifier());
        assertEquals(1L, action.getIncidentId());
        assertEquals("test-user", action.getTriggeredBy());
        verify(actionRepository).save(any(ResponseAction.class));
        verify(agentCommandService).sendKillProcessCommand(eq("agent-token-123"), eq("1234"), eq("malware.exe"), anyString());
    }

    @Test
    void shouldExecuteQuarantineFile() {
        when(actionRepository.save(any(ResponseAction.class))).thenAnswer(inv -> inv.getArgument(0));
        when(agentRepository.findByHostname("WIN-HOST")).thenReturn(Optional.of(agent));
        when(agentCommandService.sendQuarantineFileCommand(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));

        ResponseAction action = responseService.executeQuarantineFile(1L, 1L, "C:\\test.encrypted", "Ransomware", "test-user");

        assertEquals("QUARANTINE_FILE", action.getActionType());
        assertEquals("C:\\test.encrypted", action.getTargetIdentifier());
        verify(agentCommandService).sendQuarantineFileCommand(eq("agent-token-123"), eq("C:\\test.encrypted"), eq("Ransomware"), anyString());
    }

    @Test
    void shouldExecuteIsolateEndpoint() {
        when(actionRepository.save(any(ResponseAction.class))).thenAnswer(inv -> inv.getArgument(0));
        when(agentRepository.findByHostname("WIN-HOST")).thenReturn(Optional.of(agent));
        when(agentCommandService.sendIsolateEndpointCommand(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));

        ResponseAction action = responseService.executeIsolateEndpoint(1L, 1L, "WIN-HOST", "Critical", "test-user");

        assertEquals("ISOLATE_ENDPOINT", action.getActionType());
        assertEquals("WIN-HOST", action.getTargetIdentifier());
        verify(agentCommandService).sendIsolateEndpointCommand(eq("agent-token-123"), eq("WIN-HOST"), eq("Critical"), anyString());
    }

    @Test
    void shouldExecuteProtectFile() {
        when(actionRepository.save(any(ResponseAction.class))).thenAnswer(inv -> inv.getArgument(0));
        when(protectedFileService.isProtected("C:\\critical.dll")).thenReturn(false);
        when(protectedFileService.protectFile(anyString(), anyString())).thenReturn(new com.cynera.backend.detection.ransomware.ProtectedFile("C:\\critical.dll", "Protected"));
        when(agentRepository.findByHostname("WIN-HOST")).thenReturn(Optional.of(agent));
        when(agentCommandService.sendProtectFileCommand(anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));

        ResponseAction action = responseService.executeProtectFile(1L, 1L, "C:\\critical.dll", "test-user");

        assertEquals("PROTECT_FILE", action.getActionType());
        verify(protectedFileService).protectFile("C:\\critical.dll", "Protected via response action");
        verify(agentCommandService).sendProtectFileCommand(eq("agent-token-123"), eq("C:\\critical.dll"), anyString());
    }

    @Test
    void shouldExecuteUnprotectFile() {
        when(actionRepository.save(any(ResponseAction.class))).thenAnswer(inv -> inv.getArgument(0));
        when(agentRepository.findByHostname("WIN-HOST")).thenReturn(Optional.of(agent));
        when(agentCommandService.sendUnprotectFileCommand(anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));

        ResponseAction action = responseService.executeUnprotectFile(1L, 1L, "C:\\temp.txt", "test-user");

        assertEquals("UNPROTECT_FILE", action.getActionType());
        verify(protectedFileService).unprotectFile("C:\\temp.txt");
        verify(agentCommandService).sendUnprotectFileCommand(eq("agent-token-123"), eq("C:\\temp.txt"), anyString());
    }

    @Test
    void shouldExecuteBlockNetwork() {
        when(actionRepository.save(any(ResponseAction.class))).thenAnswer(inv -> inv.getArgument(0));

        ResponseAction action = responseService.executeBlockNetworkConnection(1L, 1L, "192.168.1.100", 4444, "test-user");

        assertEquals("BLOCK_NETWORK", action.getActionType());
        assertEquals("192.168.1.100:4444", action.getTargetIdentifier());
    }

    @Test
    void shouldHandleCommandResultSuccess() {
        ResponseAction action = new ResponseAction(
                "action-123", "KILL_PROCESS", "malware.exe",
                Map.of(), 1L, 1L, "user", "agent-token", "corr-1"
        );
        when(actionRepository.findByActionId("action-123")).thenReturn(Optional.of(action));
        when(actionRepository.save(any(ResponseAction.class))).thenAnswer(inv -> inv.getArgument(0));

        responseService.handleCommandResult("agent-token", "action-123", true, "Killed", Map.of("exitCode", 0));

        assertEquals(ResponseAction.Status.COMPLETED, action.getStatus());
        assertEquals("Killed", action.getResultMessage());
        assertNotNull(action.getCompletedAt());
    }

    @Test
    void shouldHandleCommandResultFailure() {
        ResponseAction action = new ResponseAction(
                "action-123", "QUARANTINE_FILE", "C:\\bad.exe",
                Map.of(), 1L, 1L, "user", "agent-token", "corr-1"
        );
        when(actionRepository.findByActionId("action-123")).thenReturn(Optional.of(action));
        when(actionRepository.save(any(ResponseAction.class))).thenAnswer(inv -> inv.getArgument(0));

        responseService.handleCommandResult("agent-token", "action-123", false, "File not found", Map.of());

        assertEquals(ResponseAction.Status.FAILED, action.getStatus());
        assertEquals("File not found", action.getResultMessage());
    }

    @Test
    void shouldGetActionsForIncident() {
        ResponseAction action1 = new ResponseAction("a1", "KILL_PROCESS", "p1", Map.of(), 1L, 1L, "u", "t", "c");
        ResponseAction action2 = new ResponseAction("a2", "QUARANTINE_FILE", "f1", Map.of(), 1L, 1L, "u", "t", "c");
        when(actionRepository.findByIncidentId(1L)).thenReturn(List.of(action1, action2));

        List<ResponseAction> actions = responseService.getActionsForIncident(1L);

        assertEquals(2, actions.size());
    }

    @Test
    void shouldCancelPendingAction() {
        ResponseAction action = new ResponseAction("a1", "KILL_PROCESS", "p1", Map.of(), 1L, 1L, "u", "t", "c");
        action.setStatus(ResponseAction.Status.PENDING);
        when(actionRepository.findById(1L)).thenReturn(Optional.of(action));
        when(actionRepository.save(any(ResponseAction.class))).thenAnswer(inv -> inv.getArgument(0));

        responseService.cancelAction(1L, "User cancelled");

        assertEquals(ResponseAction.Status.CANCELLED, action.getStatus());
        assertEquals("Cancelled: User cancelled", action.getResultMessage());
    }

    @Test
    void shouldNotCancelCompletedAction() {
        ResponseAction action = new ResponseAction("a1", "KILL_PROCESS", "p1", Map.of(), 1L, 1L, "u", "t", "c");
        action.setStatus(ResponseAction.Status.COMPLETED);
        when(actionRepository.findById(1L)).thenReturn(Optional.of(action));

        responseService.cancelAction(1L, "User cancelled");

        assertEquals(ResponseAction.Status.COMPLETED, action.getStatus());
    }
}