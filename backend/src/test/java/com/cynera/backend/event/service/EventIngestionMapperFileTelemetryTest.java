package com.cynera.backend.event.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.event.dto.EventRequest;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class EventIngestionMapperFileTelemetryTest {

    private final EventIngestionMapper mapper = new EventIngestionMapper();

    @Test
    void shouldMapFileTelemetryFieldsToEventRequest() {

        Instant timestamp = Instant.parse("2026-09-07T10:00:00Z");

        AgentEventRequest request = new AgentEventRequest(
                "FILE_MODIFIED",
                "WIN-01",
                "ana",
                "winword.exe",
                null,
                timestamp,
                "C:\\Users\\ana\\document.docx",
                "MODIFIED",
                5000L,
                "sha256-value"
        );

        EventRequest result = mapper.toEventRequest(request);

        assertEquals("FILE_MODIFIED", result.eventType());
        assertEquals("WIN-01", result.hostname());
        assertEquals("ana", result.username());
        assertEquals("winword.exe", result.processName());
        assertEquals(timestamp, result.timestamp());

        assertEquals(
                "C:\\Users\\ana\\document.docx",
                result.filePath()
        );
        assertEquals("MODIFIED", result.fileAction());
        assertEquals(5000L, result.fileSize());
        assertEquals("sha256-value", result.fileHash());
    }

    @Test
    void shouldGenerateTimestampWhenMissing() {

        AgentEventRequest request = new AgentEventRequest(
                "FILE_CREATED",
                "WIN-01",
                null,
                null,
                null,
                null,
                "C:\\temp\\test.txt",
                "CREATED",
                100L,
                null
        );

        EventRequest result = mapper.toEventRequest(request);

        assertNotNull(result.timestamp());
        assertEquals("FILE_CREATED", result.eventType());
        assertEquals("CREATED", result.fileAction());
    }
}