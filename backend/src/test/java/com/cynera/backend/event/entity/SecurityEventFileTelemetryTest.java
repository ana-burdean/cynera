package com.cynera.backend.event.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class SecurityEventFileTelemetryTest {

    @Test
    void shouldStoreFileTelemetryFields() {

        Instant timestamp = Instant.parse("2026-09-07T10:00:00Z");

        SecurityEvent event = new SecurityEvent(
                timestamp,
                "FILE_MODIFIED",
                "WIN-01",
                "ana",
                "winword.exe",
                null,
                "C:\\Users\\ana\\document.docx",
                "MODIFIED",
                5000L,
                "sha256-value"
        );

        assertEquals(timestamp, event.getTimestamp());
        assertEquals("FILE_MODIFIED", event.getEventType());
        assertEquals("WIN-01", event.getHostname());

        assertEquals(
                "C:\\Users\\ana\\document.docx",
                event.getFilePath()
        );
        assertEquals("MODIFIED", event.getFileAction());
        assertEquals(5000L, event.getFileSize());
        assertEquals("sha256-value", event.getFileHash());
    }
}