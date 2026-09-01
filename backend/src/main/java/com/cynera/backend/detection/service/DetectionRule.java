package com.cynera.backend.detection.service;

import com.cynera.backend.event.entity.SecurityEvent;

import java.util.Optional;

public interface DetectionRule {

    String getRuleName();

    Optional<DetectionMatch> evaluate(SecurityEvent event);
}
