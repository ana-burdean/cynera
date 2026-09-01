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
import java.util.List;

@Service
public class DetectionService {

    private final DetectionRepository detectionRepository;
    private final SecurityEventRepository securityEventRepository;
    private final List<DetectionRule> detectionRules;

    public DetectionService(
            DetectionRepository detectionRepository,
            SecurityEventRepository securityEventRepository,
            List<DetectionRule> detectionRules
    ) {
        this.detectionRepository = detectionRepository;
        this.securityEventRepository = securityEventRepository;
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

                    Detection savedDetection = detectionRepository.save(detection);

                    return DetectionResponse.from(savedDetection);
                });
    }

    @Transactional
    public List<DetectionResponse> evaluateEvent(SecurityEvent event) {
        return detectionRules.stream()
                .flatMap(rule -> rule.evaluate(event)
                        .map(match -> createDetection(
                                event.getId(),
                                rule.getRuleName(),
                                match.severity(),
                                match.description()
                        ))
                        .stream())
                .toList();
    }

    @Transactional(readOnly = true)
    public List<DetectionResponse> getAllDetections() {
        return detectionRepository.findAll()
                .stream()
                .map(DetectionResponse::from)
                .toList();
    }
}