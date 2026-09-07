package com.cynera.backend.telemetry.file.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.dto.FileTelemetry;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.event.dto.EventIngestionResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FileTelemetryServiceTest {

    @Mock
    private AgentEventService agentEventService;

    @InjectMocks
    private FileTelemetryService fileTelemetryService;

    private static final String AGENT_TOKEN = "file-agent-token";

    private static final Instant TIMESTAMP =
            Instant.parse("2026-09-07T10:00:00Z");

    @Test
    void shouldMapCreatedFileToFileCreatedEvent() {
        FileTelemetry telemetry = new FileTelemetry(
                "WIN-FILE-01",
                "C:\\temp\\malware.txt",
                "CREATED",
                2048L,
                "abc123",
                "ana",
                "explorer.exe",
                null,
                TIMESTAMP
        );

        EventIngestionResponse response =
                new EventIngestionResponse(
                        1L,
                        "FILE_CREATED",
                        "WIN-FILE-01",
                        TIMESTAMP
                );

        when(agentEventService.ingest(
                eq(AGENT_TOKEN),
                any(AgentEventRequest.class)
        )).thenReturn(response);

        EventIngestionResponse result =
                fileTelemetryService.ingest(
                        AGENT_TOKEN,
                        telemetry
                );

        assertEquals(response, result);

        ArgumentCaptor<AgentEventRequest> captor =
                ArgumentCaptor.forClass(AgentEventRequest.class);

        verify(agentEventService).ingest(
                eq(AGENT_TOKEN),
                captor.capture()
        );

        AgentEventRequest request = captor.getValue();

        assertEquals("FILE_CREATED", request.eventType());
        assertEquals("WIN-FILE-01", request.hostname());
        assertEquals("ana", request.username());
        assertEquals("explorer.exe", request.processName());
        assertEquals("C:\\temp\\malware.txt", request.filePath());
        assertEquals("CREATED", request.fileAction());
        assertEquals(2048L, request.fileSize());
        assertEquals("abc123", request.fileHash());
        assertEquals(TIMESTAMP, request.timestamp());
    }

    @Test
    void shouldMapModifiedFileToFileModifiedEvent() {
        FileTelemetry telemetry = new FileTelemetry(
                "WIN-FILE-01",
                "C:\\temp\\test.txt",
                "MODIFIED",
                100L,
                "hash-modified",
                "ana",
                "notepad.exe",
                null,
                TIMESTAMP
        );

        fileTelemetryService.ingest(
                AGENT_TOKEN,
                telemetry
        );

        ArgumentCaptor<AgentEventRequest> captor =
                ArgumentCaptor.forClass(AgentEventRequest.class);

        verify(agentEventService).ingest(
                eq(AGENT_TOKEN),
                captor.capture()
        );

        assertEquals(
                "FILE_MODIFIED",
                captor.getValue().eventType()
        );
    }

    @Test
    void shouldMapDeletedFileToFileDeletedEvent() {
        FileTelemetry telemetry = new FileTelemetry(
                "WIN-FILE-01",
                "C:\\temp\\deleted.txt",
                "DELETED",
                512L,
                "hash-deleted",
                "ana",
                "explorer.exe",
                null,
                TIMESTAMP
        );

        fileTelemetryService.ingest(
                AGENT_TOKEN,
                telemetry
        );

        ArgumentCaptor<AgentEventRequest> captor =
                ArgumentCaptor.forClass(AgentEventRequest.class);

        verify(agentEventService).ingest(
                eq(AGENT_TOKEN),
                captor.capture()
        );

        assertEquals(
                "FILE_DELETED",
                captor.getValue().eventType()
        );
    }

    @Test
    void shouldMapRenamedFileToFileRenamedEvent() {
        FileTelemetry telemetry = new FileTelemetry(
                "WIN-FILE-01",
                "C:\\temp\\renamed.txt",
                "RENAMED",
                1024L,
                "hash-renamed",
                "ana",
                "explorer.exe",
                null,
                TIMESTAMP
        );

        fileTelemetryService.ingest(
                AGENT_TOKEN,
                telemetry
        );

        ArgumentCaptor<AgentEventRequest> captor =
                ArgumentCaptor.forClass(AgentEventRequest.class);

        verify(agentEventService).ingest(
                eq(AGENT_TOKEN),
                captor.capture()
        );

        assertEquals(
                "FILE_RENAMED",
                captor.getValue().eventType()
        );
    }

    @Test
    void shouldRejectUnsupportedFileAction() {
        FileTelemetry telemetry = new FileTelemetry(
                "WIN-FILE-01",
                "C:\\temp\\test.txt",
                "EXECUTED",
                100L,
                "hash",
                "ana",
                "explorer.exe",
                null,
                TIMESTAMP
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> fileTelemetryService.ingest(
                        AGENT_TOKEN,
                        telemetry
                )
        );
    }
}