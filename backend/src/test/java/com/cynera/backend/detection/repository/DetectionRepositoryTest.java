package com.cynera.backend.detection.repository;

import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class DetectionRepositoryTest {

    @Autowired
    private DetectionRepository detectionRepository;

    @Autowired
    private SecurityEventRepository securityEventRepository;

    @Test
    void shouldSaveAndFindDetectionByEventAndRule() {
        SecurityEvent event = new SecurityEvent(
                Instant.now(),
                "PROCESS_CREATED",
                "HOST-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        SecurityEvent savedEvent =
                securityEventRepository.save(event);

        Detection detection = new Detection(
                savedEvent,
                "SUSPICIOUS_POWERSHELL",
                Severity.MEDIUM,
                "PowerShell execution detected",
                Instant.now()
        );

        detectionRepository.save(detection);

        Detection found = detectionRepository
                .findByEventIdAndRule(
                        savedEvent.getId(),
                        "SUSPICIOUS_POWERSHELL"
                )
                .orElseThrow();

        assertNotNull(found.getId());
        assertEquals(
                savedEvent.getId(),
                found.getEvent().getId()
        );
        assertEquals(
                "SUSPICIOUS_POWERSHELL",
                found.getRule()
        );
        assertEquals(
                Severity.MEDIUM,
                found.getSeverity()
        );
    }

    @Test
    void shouldReturnEmptyWhenDetectionDoesNotExist() {
        SecurityEvent event = new SecurityEvent(
                Instant.now(),
                "PROCESS_CREATED",
                "HOST-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        SecurityEvent savedEvent =
                securityEventRepository.save(event);

        assertTrue(
                detectionRepository
                        .findByEventIdAndRule(
                                savedEvent.getId(),
                                "UNKNOWN_RULE"
                        )
                        .isEmpty()
        );
    }
}
