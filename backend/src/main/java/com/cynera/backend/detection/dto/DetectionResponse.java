package com.cynera.backend.detection.dto;

import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.model.Severity;

import java.time.Instant;

public record DetectionResponse(
        Long id,
        Long eventId,
        String rule,
        Severity severity,
        String description,
        Instant detectedAt
) {

    public static DetectionResponse from(Detection detection) {
        return new DetectionResponse(
                detection.getId(),
                detection.getEvent().getId(),
                detection.getRule(),
                detection.getSeverity(),
                detection.getDescription(),
                detection.getDetectedAt()
        );
    }
}