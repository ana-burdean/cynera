package com.cynera.backend.detection.service;

import com.cynera.backend.detection.dto.DetectionResponse;
import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.detection.repository.DetectionRepository;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DetectionServiceTest {

    @Mock
    private DetectionRepository detectionRepository;

    @Mock
    private SecurityEventRepository securityEventRepository;

    @Mock
    private DetectionRule detectionRule;

    @Mock
    private SecurityEvent event;

    private DetectionService detectionService;

    @BeforeEach
    void setUp() {
        detectionService = new DetectionService(
                detectionRepository,
                securityEventRepository,
                List.of(detectionRule)
        );
    }

    @Test
    void shouldEvaluateMatchingRuleAndCreateDetection() {
        when(event.getId()).thenReturn(1L);

        when(detectionRule.getRuleName())
                .thenReturn("TEST_RULE");

        when(detectionRule.evaluate(event))
                .thenReturn(Optional.of(
                        new DetectionMatch(
                                Severity.HIGH,
                                "Test detection"
                        )
                ));

        when(securityEventRepository.findById(1L))
                .thenReturn(Optional.of(event));

        when(detectionRepository.findByEventIdAndRule(
                1L,
                "TEST_RULE"
        )).thenReturn(Optional.empty());

        when(detectionRepository.save(any(Detection.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        List<DetectionResponse> responses =
                detectionService.evaluateEvent(event);

        assertEquals(1, responses.size());

        DetectionResponse response = responses.getFirst();

        assertEquals(1L, response.eventId());
        assertEquals("TEST_RULE", response.rule());
        assertEquals(Severity.HIGH, response.severity());
        assertEquals("Test detection", response.description());

        verify(detectionRule).evaluate(event);
        verify(securityEventRepository).findById(1L);
        verify(detectionRepository)
                .findByEventIdAndRule(1L, "TEST_RULE");
        verify(detectionRepository).save(any(Detection.class));
    }

    @Test
    void shouldIgnoreRuleWhenThereIsNoMatch() {
        when(detectionRule.evaluate(event))
                .thenReturn(Optional.empty());

        List<DetectionResponse> responses =
                detectionService.evaluateEvent(event);

        assertTrue(responses.isEmpty());

        verify(detectionRule).evaluate(event);

        verifyNoInteractions(
                securityEventRepository,
                detectionRepository
        );
    }

    @Test
    void shouldReturnExistingDetectionAndNotCreateDuplicate() {
        when(event.getId()).thenReturn(1L);

        when(detectionRule.getRuleName())
                .thenReturn("TEST_RULE");

        when(detectionRule.evaluate(event))
                .thenReturn(Optional.of(
                        new DetectionMatch(
                                Severity.HIGH,
                                "Test detection"
                        )
                ));

        when(securityEventRepository.findById(1L))
                .thenReturn(Optional.of(event));

        Detection existingDetection = new Detection(
                event,
                "TEST_RULE",
                Severity.HIGH,
                "Test detection",
                Instant.parse("2026-09-01T12:00:00Z")
        );

        when(detectionRepository.findByEventIdAndRule(
                1L,
                "TEST_RULE"
        )).thenReturn(Optional.of(existingDetection));

        List<DetectionResponse> responses =
                detectionService.evaluateEvent(event);

        assertEquals(1, responses.size());

        DetectionResponse response = responses.getFirst();

        assertEquals(1L, response.eventId());
        assertEquals("TEST_RULE", response.rule());
        assertEquals(Severity.HIGH, response.severity());
        assertEquals("Test detection", response.description());

        verify(detectionRepository)
                .findByEventIdAndRule(1L, "TEST_RULE");

        verify(detectionRepository, never())
                .save(any(Detection.class));
    }

    @Test
    void shouldGetAllDetections() {
        when(event.getId()).thenReturn(1L);

        Detection detection = new Detection(
                event,
                "TEST_RULE",
                Severity.MEDIUM,
                "Test detection",
                Instant.parse("2026-09-01T12:00:00Z")
        );

        when(detectionRepository.findAll())
                .thenReturn(List.of(detection));

        List<DetectionResponse> responses =
                detectionService.getAllDetections();

        assertEquals(1, responses.size());

        DetectionResponse response = responses.getFirst();

        assertEquals(1L, response.eventId());
        assertEquals("TEST_RULE", response.rule());
        assertEquals(Severity.MEDIUM, response.severity());
        assertEquals("Test detection", response.description());

        verify(detectionRepository).findAll();
    }
}
