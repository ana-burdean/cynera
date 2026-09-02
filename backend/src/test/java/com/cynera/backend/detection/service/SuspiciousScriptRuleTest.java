package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SuspiciousScriptRuleTest {

    private final SuspiciousScriptRule rule =
            new SuspiciousScriptRule();

    @Test
    void shouldDetectPowerShellScript() {
        SecurityEvent event = createEvent("script.ps1");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.MEDIUM, result.get().severity());
        assertEquals(
                "Script execution detected",
                result.get().description()
        );
    }

    @Test
    void shouldDetectBatchScript() {
        SecurityEvent event = createEvent("payload.bat");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.MEDIUM, result.get().severity());
    }

    @Test
    void shouldDetectCmdScript() {
        SecurityEvent event = createEvent("script.cmd");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectVbsScript() {
        SecurityEvent event = createEvent("script.vbs");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectJavaScript() {
        SecurityEvent event = createEvent("script.js");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldBeCaseInsensitive() {
        SecurityEvent event = createEvent("SCRIPT.PS1");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldNotDetectExecutable() {
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

    @Test
    void shouldNotDetectScriptExtensionInsideFilename() {
        SecurityEvent event = createEvent("script.ps1.exe");

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