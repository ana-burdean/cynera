package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class OfficeSpawnedShellRuleTest {

    private final OfficeSpawnedShellRule rule =
            new OfficeSpawnedShellRule();

    @Test
    void shouldDetectWordSpawningPowerShell() {
        SecurityEvent event = createEvent(
                "powershell.exe",
                "WINWORD.EXE"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
        assertEquals(
                "Office application spawned a command shell",
                result.get().description()
        );
    }

    @Test
    void shouldDetectExcelSpawningCmd() {
        SecurityEvent event = createEvent(
                "cmd.exe",
                "EXCEL.EXE"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
    }

    @Test
    void shouldDetectPowerPointSpawningPwsh() {
        SecurityEvent event = createEvent(
                "pwsh.exe",
                "POWERPNT.EXE"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldDetectOutlookSpawningCmd() {
        SecurityEvent event = createEvent(
                "cmd.exe",
                "OUTLOOK.EXE"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldBeCaseInsensitive() {
        SecurityEvent event = createEvent(
                "PowerShell.EXE",
                "WinWord.EXE"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
    }

    @Test
    void shouldNotDetectExplorerSpawningPowerShell() {
        SecurityEvent event = createEvent(
                "powershell.exe",
                "explorer.exe"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldNotDetectOfficeSpawningNotepad() {
        SecurityEvent event = createEvent(
                "notepad.exe",
                "WINWORD.EXE"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldNotDetectNullProcessName() {
        SecurityEvent event = createEvent(
                null,
                "WINWORD.EXE"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldNotDetectNullParentProcessName() {
        SecurityEvent event = createEvent(
                "powershell.exe",
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