package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SuspiciousNetworkProcessRuleTest {

    private final SuspiciousNetworkProcessRule rule =
            new SuspiciousNetworkProcessRule();

    @Test
    void shouldDetectCurlExe() {
        SecurityEvent event = createEvent("curl.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
        assertEquals(
                "Suspicious network-capable process detected",
                result.get().description()
        );
    }

    @Test
    void shouldDetectCurl() {
        SecurityEvent event = createEvent("curl");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectWgetExe() {
        SecurityEvent event = createEvent("wget.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectWget() {
        SecurityEvent event = createEvent("wget");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectCertutil() {
        SecurityEvent event = createEvent("certutil.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectBitsadmin() {
        SecurityEvent event = createEvent("bitsadmin.exe");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldBeCaseInsensitive() {
        SecurityEvent event = createEvent("CURL.EXE");

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
