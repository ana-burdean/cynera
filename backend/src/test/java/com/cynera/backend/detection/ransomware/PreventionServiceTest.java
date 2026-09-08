package com.cynera.backend.detection.ransomware;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.entity.AgentCommandEntity;
import com.cynera.backend.agent.repository.AgentRepository;
import com.cynera.backend.agent.service.AgentCommandService;
import com.cynera.backend.detection.entity.SecurityIncident;
import com.cynera.backend.detection.model.RiskScore;
import com.cynera.backend.detection.service.DetectionMatch;
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
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PreventionServiceTest {

    @Mock
    private AgentCommandService agentCommandService;

    @Mock
    private AgentRepository agentRepository;

    @Mock
    private ProtectedFileService protectedFileService;

    @InjectMocks
    private PreventionService preventionService;

    private Agent agent;
    private SecurityEvent event;
    private SecurityIncident incident;

    @BeforeEach
    void setUp() {
        agent = new Agent("TestAgent", "WIN-HOST", "agent-token-123", true, Instant.now());
        setId(agent, 1L);

        event = new SecurityEvent(
                Instant.now(),
                "FILE_MODIFIED",
                "WIN-HOST",
                "testuser",
                "ransomware.exe",
                "explorer.exe",
                "C:\\test.encrypted",
                "MODIFIED",
                1024L,
                "hash",
                null, null, null,
                null, null, null, null,
                null, null, null, null
        );

        incident = new SecurityIncident("WIN-HOST", "testuser", RiskScore.CRITICAL, Instant.now());
        setId(incident, 1L);
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
    void shouldHandleCriticalRansomwareIncident() {
        when(agentRepository.findByHostname("WIN-HOST")).thenReturn(Optional.of(agent));
        when(agentCommandService.sendKillProcessCommand(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));
        when(agentCommandService.sendQuarantineFileCommand(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));
        when(agentCommandService.sendIsolateEndpointCommand(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));

        DetectionMatch match = new DetectionMatch(
                com.cynera.backend.detection.model.Severity.CRITICAL,
                "Ransomware-like activity detected",
                "RANSOMWARE_FILE_ENCRYPTION",
                event
        );

        preventionService.handleCriticalRansomwareIncident(incident, List.of(match));

        verify(agentCommandService).sendKillProcessCommand(eq("agent-token-123"), anyString(), eq("ransomware.exe"), anyString());
        verify(agentCommandService).sendQuarantineFileCommand(eq("agent-token-123"), eq("C:\\test.encrypted"), anyString(), anyString());
        verify(agentCommandService).sendIsolateEndpointCommand(eq("agent-token-123"), eq("WIN-HOST"), anyString(), anyString());
    }

    @Test
    void shouldNotHandleIncidentWithoutRansomwareMatch() {
        DetectionMatch match = new DetectionMatch(
                com.cynera.backend.detection.model.Severity.HIGH,
                "Other detection",
                "OTHER_RULE",
                event
        );

        preventionService.handleCriticalRansomwareIncident(incident, List.of(match));

        verifyNoInteractions(agentCommandService);
    }

    @Test
    void shouldNotHandleIncidentWhenEventIsNull() {
        DetectionMatch match = new DetectionMatch(
                com.cynera.backend.detection.model.Severity.CRITICAL,
                "Ransomware-like activity detected",
                "RANSOMWARE_FILE_ENCRYPTION",
                null
        );

        preventionService.handleCriticalRansomwareIncident(incident, List.of(match));

        verifyNoInteractions(agentCommandService);
    }

    @Test
    void shouldHandleHighSeverityFileActivity() {
        when(agentCommandService.sendKillProcessCommand(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));
        when(agentCommandService.sendQuarantineFileCommand(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));

        preventionService.handleHighSeverityFileActivity("agent-token-123", event, "High severity activity");

        verify(agentCommandService).sendKillProcessCommand(eq("agent-token-123"), anyString(), eq("ransomware.exe"), anyString());
        verify(agentCommandService).sendQuarantineFileCommand(eq("agent-token-123"), eq("C:\\test.encrypted"), eq("High severity activity"), anyString());
    }

    @Test
    void shouldProtectCriticalFiles() {
        when(protectedFileService.isProtected("C:\\test.exe")).thenReturn(false);
        when(protectedFileService.protectFile("C:\\test.exe", "Auto-protected by prevention service"))
                .thenReturn(new ProtectedFile("C:\\test.exe", "Auto-protected"));
        when(agentCommandService.sendProtectFileCommand(anyString(), anyString(), anyString()))
                .thenReturn(mock(AgentCommandEntity.class));

        preventionService.protectCriticalFiles("agent-token-123", List.of("C:\\test.exe"));

        verify(protectedFileService).isProtected("C:\\test.exe");
        verify(protectedFileService).protectFile("C:\\test.exe", "Auto-protected by prevention service");
        verify(agentCommandService).sendProtectFileCommand(eq("agent-token-123"), eq("C:\\test.exe"), anyString());
    }

    @Test
    void shouldCheckIfFileProtected() {
        when(protectedFileService.isProtected("C:\\test.exe")).thenReturn(true);

        assertTrue(preventionService.isFileProtected("C:\\test.exe"));
    }

    @Test
    void shouldInitializeSystemProtection() {
        preventionService.initializeSystemProtection();

        verify(protectedFileService).initializeDefaultProtectedFiles();
    }
}