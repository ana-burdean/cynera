package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;

public record DetectionMatch(
        Severity severity,
        String description,
        String rule,
        SecurityEvent event
) {
    public DetectionMatch(Severity severity, String description) {
        this(severity, description, null, null);
    }

    public DetectionMatch(Severity severity, String description, String rule, SecurityEvent event) {
        this.severity = severity;
        this.description = description;
        this.rule = rule;
        this.event = event;
    }
}
