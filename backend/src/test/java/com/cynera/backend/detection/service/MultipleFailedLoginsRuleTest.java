package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class MultipleFailedLoginsRuleTest {

    private final MultipleFailedLoginsRule rule =
            new MultipleFailedLoginsRule();

    @Test
    void shouldDetectFailedLogin() {
        SecurityEvent event = createEvent("FAILED_LOGIN");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
        assertEquals(
                "Failed login attempt detected",
                result.get().description()
        );
    }

    @Test
    void shouldBeCaseInsensitive() {
        SecurityEvent event = createEvent("failed_login");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldNotDetectSuccessfulLogin() {
        SecurityEvent event = createEvent("SUCCESSFUL_LOGIN");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldNotDetectProcessCreated() {
        SecurityEvent event = createEvent("PROCESS_CREATED");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldNotDetectNullEventType() {
        SecurityEvent event = createEvent(null);

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    private SecurityEvent createEvent(String eventType) {
        return new SecurityEvent(
                Instant.parse("2026-09-01T12:00:00Z"),
                eventType,
                "DESKTOP-01",
                "ana",
                "unknown.exe",
                "explorer.exe"
        );
    }
}
