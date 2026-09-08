package com.cynera.backend.detection.service;

import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.entity.SecurityIncident;
import com.cynera.backend.detection.model.RiskScore;
import com.cynera.backend.detection.ransomware.PreventionService;
import com.cynera.backend.detection.repository.SecurityIncidentRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
public class SecurityIncidentService {

    private final SecurityIncidentRepository securityIncidentRepository;
    private final RiskAggregator riskAggregator;
    private final PreventionService preventionService;

    public SecurityIncidentService(
            SecurityIncidentRepository securityIncidentRepository,
            RiskAggregator riskAggregator,
            PreventionService preventionService
    ) {
        this.securityIncidentRepository = securityIncidentRepository;
        this.riskAggregator = riskAggregator;
        this.preventionService = preventionService;
    }

    @Transactional
    public SecurityIncident createIncident(
            String hostname,
            String username,
            List<Detection> detections
    ) {
        RiskScore riskScore = riskAggregator.aggregate(
                detections.stream()
                        .map(Detection::getSeverity)
                        .toList()
        );

        SecurityIncident incident = new SecurityIncident(
                hostname,
                username,
                riskScore,
                Instant.now()
        );

        SecurityIncident savedIncident =
                securityIncidentRepository.save(incident);

        if (riskScore == RiskScore.CRITICAL) {
            List<DetectionMatch> detectionMatches = detections.stream()
                    .map(detection -> new DetectionMatch(
                            detection.getSeverity(),
                            detection.getDescription(),
                            detection.getRule(),
                            detection.getEvent()
                    ))
                    .toList();

            preventionService.handleCriticalRansomwareIncident(
                    savedIncident,
                    detectionMatches
            );
        }

        return savedIncident;
    }
}