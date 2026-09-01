package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SuspiciousPowerShellRuleTest {

    private final SuspiciousPowerShellRule rule =
            new SuspiciousPowerShellRule();

    @Test
    void shouldDetectPowerShell() {
        SecurityEvent event = createEvent("powershell.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.MEDIUM, result.get().severity());
        assertEquals(
                "PowerShell execution detected",
                result.get().description()
        );
    }

    @Test
    void shouldDetectPwsh() {
        SecurityEvent event = createEvent("pwsh.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.MEDIUM, result.get().severity());
    }

    @Test
    void shouldBeCaseInsensitive() {
        SecurityEvent event = createEvent("PowerShell.EXE");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldNotDetectNotepad() {
        SecurityEvent event = createEvent("notepad.exe");

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