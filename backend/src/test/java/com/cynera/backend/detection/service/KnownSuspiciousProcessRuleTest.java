package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class KnownSuspiciousProcessRuleTest {

    private final KnownSuspiciousProcessRule rule =
            new KnownSuspiciousProcessRule();

    @Test
    void shouldDetectMimikatz() {
        SecurityEvent event = createEvent("mimikatz.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
        assertEquals(
                "Known suspicious process detected",
                result.get().description()
        );
    }

    @Test
    void shouldDetectProcDump() {
        SecurityEvent event = createEvent("procdump.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectPsExec() {
        SecurityEvent event = createEvent("psexec.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectRubeus() {
        SecurityEvent event = createEvent("rubeus.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectCobaltStrike() {
        SecurityEvent event = createEvent("cobaltstrike.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldBeCaseInsensitive() {
        SecurityEvent event = createEvent("MIMIKATZ.EXE");

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
    void shouldNotDetectPowerShell() {
        SecurityEvent event = createEvent("powershell.exe");

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
