package com.cynera.backend.detection.service;

import com.cynera.backend.detection.dto.DetectionResponse;
import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.detection.repository.DetectionRepository;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Service
public class DetectionService {

    private final DetectionRepository detectionRepository;
    private final SecurityEventRepository securityEventRepository;
    private final SecurityIncidentService securityIncidentService;
    private final List<DetectionRule> detectionRules;

    public DetectionService(
            DetectionRepository detectionRepository,
            SecurityEventRepository securityEventRepository,
            SecurityIncidentService securityIncidentService,
            List<DetectionRule> detectionRules
    ) {
        this.detectionRepository = detectionRepository;
        this.securityEventRepository = securityEventRepository;
        this.securityIncidentService = securityIncidentService;
        this.detectionRules = detectionRules;
    }

    @Transactional
    public DetectionResponse createDetection(
            Long eventId,
            String rule,
            Severity severity,
            String description
    ) {
        SecurityEvent event = securityEventRepository.findById(eventId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Security event not found: " + eventId
                ));

        return detectionRepository.findByEventIdAndRule(eventId, rule)
                .map(DetectionResponse::from)
                .orElseGet(() -> {
                    Detection detection = new Detection(
                            event,
                            rule,
                            severity,
                            description,
                            Instant.now()
                    );

                    Detection savedDetection =
                            detectionRepository.save(detection);

                    return DetectionResponse.from(savedDetection);
                });
    }

    @Transactional
    public List<DetectionResponse> evaluateEvent(SecurityEvent event) {
        List<Detection> detections = new ArrayList<>();

        detectionRules.forEach(rule ->
                rule.evaluate(event).ifPresent(match -> {
                    Detection detection =
                            createDetectionEntity(
                                    event,
                                    rule.getRuleName(),
                                    match.severity(),
                                    match.description()
                            );

                    detections.add(detection);
                })
        );

        if (!detections.isEmpty()) {
            securityIncidentService.createIncident(
                    event.getHostname(),
                    event.getUsername(),
                    detections
            );
        }

        return detections.stream()
                .map(DetectionResponse::from)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<DetectionResponse> getAllDetections() {
        return detectionRepository.findAll()
                .stream()
                .map(DetectionResponse::from)
                .toList();
    }

    private Detection createDetectionEntity(
            SecurityEvent event,
            String rule,
            Severity severity,
            String description
    ) {
        return detectionRepository.findByEventIdAndRule(
                        event.getId(),
                        rule
                )
                .orElseGet(() -> {
                    Detection detection = new Detection(
                            event,
                            rule,
                            severity,
                            description,
                            Instant.now()
                    );

                    return detectionRepository.save(detection);
                });
    }
}