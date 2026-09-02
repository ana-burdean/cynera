package com.cynera.backend.detection.service;

import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.entity.SecurityIncident;
import com.cynera.backend.detection.model.RiskScore;
import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.detection.repository.SecurityIncidentRepository;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SecurityIncidentServiceTest {

    @Mock
    private SecurityIncidentRepository securityIncidentRepository;

    @Mock
    private RiskAggregator riskAggregator;

    private SecurityIncidentService securityIncidentService;

    @BeforeEach
    void setUp() {
        securityIncidentService = new SecurityIncidentService(
                securityIncidentRepository,
                riskAggregator
        );
    }

    @Test
    void shouldCreateHighRiskIncident() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        Detection detection = new Detection(
                event,
                "SUSPICIOUS_POWERSHELL",
                Severity.HIGH,
                "PowerShell execution detected",
                Instant.parse("2026-09-02T10:00:01Z")
        );

        when(riskAggregator.aggregate(List.of(Severity.HIGH)))
                .thenReturn(RiskScore.HIGH);

        when(securityIncidentRepository.save(any(SecurityIncident.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        SecurityIncident result =
                securityIncidentService.createIncident(
                        "DESKTOP-01",
                        "ana",
                        List.of(detection)
                );

        assertEquals(
                "DESKTOP-01",
                result.getHostname()
        );

        assertEquals(
                "ana",
                result.getUsername()
        );

        assertEquals(
                RiskScore.HIGH,
                result.getRiskScore()
        );

        verify(riskAggregator)
                .aggregate(List.of(Severity.HIGH));

        verify(securityIncidentRepository)
                .save(any(SecurityIncident.class));
    }

    @Test
    void shouldCreateCriticalIncidentFromMultipleDetections() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        Detection mediumDetection = new Detection(
                event,
                "SUSPICIOUS_POWERSHELL",
                Severity.MEDIUM,
                "PowerShell execution detected",
                Instant.parse("2026-09-02T10:00:01Z")
        );

        Detection highDetection = new Detection(
                event,
                "SUSPICIOUS_PARENT_PROCESS",
                Severity.HIGH,
                "Suspicious parent process detected",
                Instant.parse("2026-09-02T10:00:02Z")
        );

        when(riskAggregator.aggregate(
                List.of(Severity.MEDIUM, Severity.HIGH)
        )).thenReturn(RiskScore.CRITICAL);

        when(securityIncidentRepository.save(any(SecurityIncident.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        SecurityIncident result =
                securityIncidentService.createIncident(
                        "DESKTOP-01",
                        "ana",
                        List.of(
                                mediumDetection,
                                highDetection
                        )
                );

        assertEquals(
                RiskScore.CRITICAL,
                result.getRiskScore()
        );

        verify(riskAggregator)
                .aggregate(
                        List.of(
                                Severity.MEDIUM,
                                Severity.HIGH
                        )
                );

        verify(securityIncidentRepository)
                .save(any(SecurityIncident.class));
    }

    @Test
    void shouldPassCorrectHostAndUserToIncident() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "PROCESS_CREATED",
                "SERVER-01",
                "admin",
                "cmd.exe",
                "explorer.exe"
        );

        Detection detection = new Detection(
                event,
                "SUSPICIOUS_CMD",
                Severity.HIGH,
                "CMD execution detected",
                Instant.parse("2026-09-02T10:00:01Z")
        );

        when(riskAggregator.aggregate(List.of(Severity.HIGH)))
                .thenReturn(RiskScore.HIGH);

        ArgumentCaptor<SecurityIncident> captor =
                ArgumentCaptor.forClass(SecurityIncident.class);

        when(securityIncidentRepository.save(any(SecurityIncident.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        securityIncidentService.createIncident(
                "SERVER-01",
                "admin",
                List.of(detection)
        );

        verify(securityIncidentRepository)
                .save(captor.capture());

        SecurityIncident savedIncident = captor.getValue();

        assertEquals(
                "SERVER-01",
                savedIncident.getHostname()
        );

        assertEquals(
                "admin",
                savedIncident.getUsername()
        );

        assertEquals(
                RiskScore.HIGH,
                savedIncident.getRiskScore()
        );
    }

    @Test
    void shouldCreateLowRiskIncidentWhenThereAreNoDetections() {
        when(riskAggregator.aggregate(List.of()))
                .thenReturn(RiskScore.LOW);

        when(securityIncidentRepository.save(any(SecurityIncident.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        SecurityIncident result =
                securityIncidentService.createIncident(
                        "DESKTOP-01",
                        "ana",
                        List.of()
                );

        assertEquals(
                RiskScore.LOW,
                result.getRiskScore()
        );

        verify(riskAggregator)
                .aggregate(List.of());

        verify(securityIncidentRepository)
                .save(any(SecurityIncident.class));
    }
}