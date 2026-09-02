package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class MultipleFailedLoginsRuleTest {

    @Mock
    private SecurityEventRepository securityEventRepository;

    private MultipleFailedLoginsRule rule;

    @BeforeEach
    void setUp() {
        rule = new MultipleFailedLoginsRule(
                securityEventRepository
        );
    }

    @Test
    void shouldDetectMultipleFailedLogins() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "FAILED_LOGIN",
                "DESKTOP-01",
                "ana",
                null,
                null
        );

        when(securityEventRepository
                .countByEventTypeAndUsernameAndHostnameAndTimestampAfter(
                        "FAILED_LOGIN",
                        "ana",
                        "DESKTOP-01",
                        Instant.parse("2026-09-02T09:55:00Z")
                ))
                .thenReturn(3L);

        Optional<DetectionMatch> result =
                rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(
                Severity.HIGH,
                result.get().severity()
        );
        assertEquals(
                "Multiple failed login attempts detected",
                result.get().description()
        );

        verify(securityEventRepository)
                .countByEventTypeAndUsernameAndHostnameAndTimestampAfter(
                        "FAILED_LOGIN",
                        "ana",
                        "DESKTOP-01",
                        Instant.parse("2026-09-02T09:55:00Z")
                );
    }

    @Test
    void shouldNotDetectWhenThereAreLessThanThreeFailedLogins() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "FAILED_LOGIN",
                "DESKTOP-01",
                "ana",
                null,
                null
        );

        when(securityEventRepository
                .countByEventTypeAndUsernameAndHostnameAndTimestampAfter(
                        "FAILED_LOGIN",
                        "ana",
                        "DESKTOP-01",
                        Instant.parse("2026-09-02T09:55:00Z")
                ))
                .thenReturn(2L);

        Optional<DetectionMatch> result =
                rule.evaluate(event);

        assertTrue(result.isEmpty());

        verify(securityEventRepository)
                .countByEventTypeAndUsernameAndHostnameAndTimestampAfter(
                        "FAILED_LOGIN",
                        "ana",
                        "DESKTOP-01",
                        Instant.parse("2026-09-02T09:55:00Z")
                );
    }

    @Test
    void shouldNotDetectDifferentEventType() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        Optional<DetectionMatch> result =
                rule.evaluate(event);

        assertTrue(result.isEmpty());

        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void shouldNotDetectWhenUsernameIsMissing() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "FAILED_LOGIN",
                "DESKTOP-01",
                null,
                null,
                null
        );

        Optional<DetectionMatch> result =
                rule.evaluate(event);

        assertTrue(result.isEmpty());

        verifyNoInteractions(securityEventRepository);
    }

    @Test
    void shouldNotDetectWhenHostnameIsMissing() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-02T10:00:00Z"),
                "FAILED_LOGIN",
                null,
                "ana",
                null,
                null
        );

        Optional<DetectionMatch> result =
                rule.evaluate(event);

        assertTrue(result.isEmpty());

        verifyNoInteractions(securityEventRepository);
    }
}