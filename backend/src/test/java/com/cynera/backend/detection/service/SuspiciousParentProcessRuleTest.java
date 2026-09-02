package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SuspiciousParentProcessRuleTest {

    private final SuspiciousParentProcessRule rule =
            new SuspiciousParentProcessRule();

    @Test
    void shouldDetectWordAsSuspiciousParent() {
        SecurityEvent event = createEvent("notepad.exe", "WINWORD.EXE");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
        assertEquals(
                "Suspicious parent process detected",
                result.get().description()
        );
    }

    @Test
    void shouldDetectExcelAsSuspiciousParent() {
        SecurityEvent event = createEvent("notepad.exe", "EXCEL.EXE");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
    }

    @Test
    void shouldDetectPowerPointAsSuspiciousParent() {
        SecurityEvent event = createEvent("notepad.exe", "POWERPNT.EXE");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectOutlookAsSuspiciousParent() {
        SecurityEvent event = createEvent("notepad.exe", "OUTLOOK.EXE");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectW3wpAsSuspiciousParent() {
        SecurityEvent event = createEvent("notepad.exe", "W3WP.EXE");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectSqlservrAsSuspiciousParent() {
        SecurityEvent event = createEvent("notepad.exe", "SQLSERVR.EXE");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldBeCaseInsensitive() {
        SecurityEvent event = createEvent(
                "notepad.exe",
                "WinWord.Exe"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldNotDetectExplorerAsParent() {
        SecurityEvent event = createEvent(
                "notepad.exe",
                "explorer.exe"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldNotDetectNullParentProcessName() {
        SecurityEvent event = createEvent(
                "notepad.exe",
                null
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    private SecurityEvent createEvent(
            String processName,
            String parentProcessName
    ) {
        return new SecurityEvent(
                Instant.parse("2026-09-01T12:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                processName,
                parentProcessName
        );
    }
}
