package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class DetectionRuleTest {

    @Test
    void shouldEvaluateMatchingPowerShellEvent() {
        DetectionRule rule =
                new SuspiciousPowerShellRule();

        SecurityEvent event = new SecurityEvent(
                Instant.now(),
                "PROCESS_CREATED",
                "HOST-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        Optional<DetectionMatch> result =
                rule.evaluate(event);

        assertTrue(result.isPresent());

        DetectionMatch match =
                result.orElseThrow();

        assertEquals(
                Severity.MEDIUM,
                match.severity()
        );

        assertEquals(
                "PowerShell execution detected",
                match.description()
        );

        assertEquals(
                "SUSPICIOUS_POWERSHELL",
                rule.getRuleName()
        );
    }

    @Test
    void shouldNotMatchUnrelatedProcess() {
        DetectionRule rule =
                new SuspiciousPowerShellRule();

        SecurityEvent event = new SecurityEvent(
                Instant.now(),
                "PROCESS_CREATED",
                "HOST-01",
                "ana",
                "notepad.exe",
                "explorer.exe"
        );

        Optional<DetectionMatch> result =
                rule.evaluate(event);

        assertTrue(result.isEmpty());
    }
}
