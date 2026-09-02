package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class EncodedPowerShellRuleTest {

    private final EncodedPowerShellRule rule =
            new EncodedPowerShellRule();

    @Test
    void shouldDetectEncodedCommand() {
        SecurityEvent event = createEvent(
                "powershell.exe -EncodedCommand SGVsbG8="
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
        assertEquals(
                "Encoded PowerShell command detected",
                result.get().description()
        );
    }

    @Test
    void shouldDetectShortEncodedCommandParameter() {
        SecurityEvent event = createEvent(
                "powershell.exe -enc SGVsbG8="
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
    }

    @Test
    void shouldDetectPwshEncodedCommand() {
        SecurityEvent event = createEvent(
                "pwsh.exe -EncodedCommand SGVsbG8="
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldBeCaseInsensitive() {
        SecurityEvent event = createEvent(
                "PowerShell.EXE -ENCODEDCOMMAND SGVsbG8="
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldNotDetectNormalPowerShell() {
        SecurityEvent event = createEvent(
                "powershell.exe -Command Get-Process"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldNotDetectNormalPwsh() {
        SecurityEvent event = createEvent(
                "pwsh.exe -Command Get-Date"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldNotDetectNullProcessName() {
        SecurityEvent event = createEvent(null);

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    private SecurityEvent createEvent(String processName) {
        return new SecurityEvent(
                Instant.parse("2026-09-01T12:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                processName,
                "explorer.exe"
        );
    }
}
