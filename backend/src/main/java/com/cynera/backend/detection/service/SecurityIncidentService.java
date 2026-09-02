package com.cynera.backend.detection.service;

import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.entity.SecurityIncident;
import com.cynera.backend.detection.model.RiskScore;
import com.cynera.backend.detection.repository.SecurityIncidentRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
public class SecurityIncidentService {

    private final SecurityIncidentRepository securityIncidentRepository;
    private final RiskAggregator riskAggregator;

    public SecurityIncidentService(
            SecurityIncidentRepository securityIncidentRepository,
            RiskAggregator riskAggregator
    ) {
        this.securityIncidentRepository = securityIncidentRepository;
        this.riskAggregator = riskAggregator;
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

        return securityIncidentRepository.save(incident);
    }
}