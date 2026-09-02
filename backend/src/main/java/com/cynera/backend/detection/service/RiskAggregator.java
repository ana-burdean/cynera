package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.RiskScore;
import com.cynera.backend.detection.model.Severity;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RiskAggregator {

    public RiskScore aggregate(List<Severity> severities) {
        if (severities == null || severities.isEmpty()) {
            return RiskScore.LOW;
        }

        int totalScore = severities.stream()
                .map(RiskScore::fromSeverity)
                .mapToInt(RiskScore::getValue)
                .sum();

        if (totalScore >= RiskScore.CRITICAL.getValue()) {
            return RiskScore.CRITICAL;
        }

        if (totalScore >= RiskScore.HIGH.getValue()) {
            return RiskScore.HIGH;
        }

        if (totalScore >= RiskScore.MEDIUM.getValue()) {
            return RiskScore.MEDIUM;
        }

        return RiskScore.LOW;
    }
}