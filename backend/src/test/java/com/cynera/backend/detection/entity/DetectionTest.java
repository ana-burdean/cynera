package com.cynera.backend.detection.entity;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class DetectionTest {

    @Test
    void shouldCreateDetection() {
        Instant timestamp = Instant.now();

        SecurityEvent event = new SecurityEvent(
                timestamp,
                "PROCESS_CREATED",
                "HOST-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        Detection detection = new Detection(
                event,
                "SUSPICIOUS_POWERSHELL",
                Severity.MEDIUM,
                "PowerShell execution detected",
                timestamp
        );

        assertNull(detection.getId());
        assertSame(event, detection.getEvent());
        assertEquals(
                "SUSPICIOUS_POWERSHELL",
                detection.getRule()
        );
        assertEquals(
                Severity.MEDIUM,
                detection.getSeverity()
        );
        assertEquals(
                "PowerShell execution detected",
                detection.getDescription()
        );
        assertEquals(
                timestamp,
                detection.getDetectedAt()
        );
    }

    @Test
    void shouldSupportDifferentSeverities() {
        SecurityEvent event = new SecurityEvent(
                Instant.now(),
                "PROCESS_CREATED",
                "HOST-01",
                "ana",
                "cmd.exe",
                "explorer.exe"
        );

        Detection detection = new Detection(
                event,
                "SUSPICIOUS_CMD",
                Severity.HIGH,
                "Command shell execution detected",
                Instant.now()
        );

        assertEquals(
                Severity.HIGH,
                detection.getSeverity()
        );
    }
}
