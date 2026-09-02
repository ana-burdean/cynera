package com.cynera.backend.detection.service;

import com.cynera.backend.detection.dto.DetectionResponse;
import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.entity.SecurityIncident;
import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.detection.repository.DetectionRepository;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DetectionServiceTest {

    @Mock
    private DetectionRepository detectionRepository;

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Mock
    private SecurityIncidentService securityIncidentService;

    @Mock
    private DetectionRule detectionRule;

    private DetectionService detectionService;

    @BeforeEach
    void setUp() {
        detectionService = new DetectionService(
                detectionRepository,
                securityEventRepository,
                securityIncidentService,
                List.of(detectionRule)
        );
    }

    @Test
    void shouldCreateDetection() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        when(securityEventRepository.findById(1L))
                .thenReturn(Optional.of(event));

        when(detectionRepository.findByEventIdAndRule(
                1L,
                "SUSPICIOUS_POWERSHELL"
        )).thenReturn(Optional.empty());

        Detection detection = new Detection(
                event,
                "SUSPICIOUS_POWERSHELL",
                Severity.MEDIUM,
                "PowerShell execution detected",
                Instant.parse("2026-09-02T10:00:01Z")
        );

        when(detectionRepository.save(any(Detection.class)))
                .thenReturn(detection);

        DetectionResponse response =
                detectionService.createDetection(
                        1L,
                        "SUSPICIOUS_POWERSHELL",
                        Severity.MEDIUM,
                        "PowerShell execution detected"
                );

        assertEquals(
                "SUSPICIOUS_POWERSHELL",
                response.rule()
        );

        assertEquals(
                Severity.MEDIUM,
                response.severity()
        );

        assertEquals(
                "PowerShell execution detected",
                response.description()
        );

        verify(detectionRepository)
                .save(any(Detection.class));

        verifyNoInteractions(securityIncidentService);
    }

    @Test
    void shouldReturnExistingDetection() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        Detection existingDetection = new Detection(
                event,
                "SUSPICIOUS_POWERSHELL",
                Severity.MEDIUM,
                "PowerShell execution detected",
                Instant.parse("2026-09-02T10:00:01Z")
        );

        when(securityEventRepository.findById(1L))
                .thenReturn(Optional.of(event));

        when(detectionRepository.findByEventIdAndRule(
                1L,
                "SUSPICIOUS_POWERSHELL"
        )).thenReturn(Optional.of(existingDetection));

        DetectionResponse response =
                detectionService.createDetection(
                        1L,
                        "SUSPICIOUS_POWERSHELL",
                        Severity.MEDIUM,
                        "PowerShell execution detected"
                );

        assertEquals(
                "SUSPICIOUS_POWERSHELL",
                response.rule()
        );

        verify(detectionRepository, never())
                .save(any(Detection.class));

        verifyNoInteractions(securityIncidentService);
    }

    @Test
    void shouldThrowWhenEventDoesNotExist() {
        when(securityEventRepository.findById(999L))
                .thenReturn(Optional.empty());

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> detectionService.createDetection(
                                999L,
                                "TEST_RULE",
                                Severity.LOW,
                                "Test description"
                        )
                );

        assertEquals(
                "Security event not found: 999",
                exception.getMessage()
        );

        verifyNoInteractions(detectionRepository);
        verifyNoInteractions(securityIncidentService);
    }

    @Test
    void shouldEvaluateEventAndCreateIncident() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        DetectionMatch match = new DetectionMatch(
                Severity.HIGH,
                "PowerShell execution detected"
        );

        when(detectionRule.evaluate(event))
                .thenReturn(Optional.of(match));

        when(detectionRule.getRuleName())
                .thenReturn("SUSPICIOUS_POWERSHELL");

        Detection detection = new Detection(
                event,
                "SUSPICIOUS_POWERSHELL",
                Severity.HIGH,
                "PowerShell execution detected",
                Instant.parse("2026-09-02T10:00:01Z")
        );

        when(detectionRepository.findByEventIdAndRule(
                event.getId(),
                "SUSPICIOUS_POWERSHELL"
        )).thenReturn(Optional.empty());

        when(detectionRepository.save(any(Detection.class)))
                .thenReturn(detection);

        SecurityIncident incident = new SecurityIncident(
                "DESKTOP-01",
                "ana",
                com.cynera.backend.detection.model.RiskScore.HIGH,
                Instant.parse("2026-09-02T10:00:02Z")
        );

        when(securityIncidentService.createIncident(
                eq("DESKTOP-01"),
                eq("ana"),
                anyList()
        )).thenReturn(incident);

        List<DetectionResponse> responses =
                detectionService.evaluateEvent(event);

        assertEquals(1, responses.size());

        assertEquals(
                "SUSPICIOUS_POWERSHELL",
                responses.get(0).rule()
        );

        assertEquals(
                Severity.HIGH,
                responses.get(0).severity()
        );

        verify(detectionRepository)
                .save(any(Detection.class));

        verify(securityIncidentService)
                .createIncident(
                        eq("DESKTOP-01"),
                        eq("ana"),
                        anyList()
                );
    }

    @Test
    void shouldNotCreateIncidentWhenNoRuleMatches() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "notepad.exe",
                "explorer.exe"
        );

        when(detectionRule.evaluate(event))
                .thenReturn(Optional.empty());

        List<DetectionResponse> responses =
                detectionService.evaluateEvent(event);

        assertTrue(responses.isEmpty());

        verifyNoInteractions(detectionRepository);
        verifyNoInteractions(securityIncidentService);
    }
}