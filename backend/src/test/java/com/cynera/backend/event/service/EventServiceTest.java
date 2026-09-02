package com.cynera.backend.event.service;

import com.cynera.backend.detection.service.DetectionService;
import com.cynera.backend.event.dto.EventRequest;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EventServiceTest {

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Mock
    private DetectionService detectionService;

    @InjectMocks
    private EventService eventService;

    @Test
    void shouldSaveEventAndEvaluateDetectionRules() {
        EventRequest request = new EventRequest(
                Instant.parse("2026-09-01T12:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        SecurityEvent savedEvent = new SecurityEvent(
                request.timestamp(),
                request.eventType(),
                request.hostname(),
                request.username(),
                request.processName(),
                request.parentProcessName()
        );

        when(securityEventRepository.save(any(SecurityEvent.class)))
                .thenReturn(savedEvent);

        var response = eventService.ingestEvent(request);

        assertNotNull(response);

        verify(securityEventRepository).save(any(SecurityEvent.class));
        verify(detectionService).evaluateEvent(savedEvent);
    }

    @Test
    void shouldMapSavedEventToResponse() {
        EventRequest request = new EventRequest(
                Instant.parse("2026-09-01T12:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "cmd.exe",
                "explorer.exe"
        );

        SecurityEvent savedEvent = new SecurityEvent(
                request.timestamp(),
                request.eventType(),
                request.hostname(),
                request.username(),
                request.processName(),
                request.parentProcessName()
        );

        when(securityEventRepository.save(any(SecurityEvent.class)))
                .thenReturn(savedEvent);

        var response = eventService.ingestEvent(request);

        assertEquals(request.timestamp(), response.timestamp());
        assertEquals(request.eventType(), response.eventType());
        assertEquals(request.hostname(), response.hostname());
        assertEquals(request.username(), response.username());
        assertEquals(request.processName(), response.processName());
        assertEquals(
                request.parentProcessName(),
                response.parentProcessName()
        );
    }

    @Test
    void shouldGetAllEvents() {
        SecurityEvent event = new SecurityEvent(
                Instant.parse("2026-09-01T12:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "notepad.exe",
                "explorer.exe"
        );

        when(securityEventRepository.findAll())
                .thenReturn(java.util.List.of(event));

        var responses = eventService.getAllEvents();

        assertEquals(1, responses.size());
        assertEquals(
                "PROCESS_CREATED",
                responses.getFirst().eventType()
        );

        verify(securityEventRepository).findAll();
    }

    @Test
    void shouldNotEvaluateDetectionBeforeEventIsSaved() {
        EventRequest request = new EventRequest(
                Instant.parse("2026-09-01T12:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        SecurityEvent savedEvent = new SecurityEvent(
                request.timestamp(),
                request.eventType(),
                request.hostname(),
                request.username(),
                request.processName(),
                request.parentProcessName()
        );

        when(securityEventRepository.save(any(SecurityEvent.class)))
                .thenReturn(savedEvent);

        eventService.ingestEvent(request);

        var inOrder = inOrder(
                securityEventRepository,
                detectionService
        );

        inOrder.verify(securityEventRepository)
                .save(any(SecurityEvent.class));

        inOrder.verify(detectionService)
                .evaluateEvent(savedEvent);
    }
}