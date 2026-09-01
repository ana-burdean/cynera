package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;

public record DetectionMatch(
        Severity severity,
        String description
) {
}
