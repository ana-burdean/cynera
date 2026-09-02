package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.RiskScore;
import com.cynera.backend.detection.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RiskAggregatorTest {

    private final RiskAggregator riskAggregator =
            new RiskAggregator();

    @Test
    void shouldReturnLowForEmptyList() {
        assertEquals(
                RiskScore.LOW,
                riskAggregator.aggregate(List.of())
        );
    }

    @Test
    void shouldAggregateSingleMediumDetection() {
        assertEquals(
                RiskScore.MEDIUM,
                riskAggregator.aggregate(
                        List.of(Severity.MEDIUM)
                )
        );
    }

    @Test
    void shouldAggregateTwoMediumDetectionsToCritical() {
        assertEquals(
                RiskScore.CRITICAL,
                riskAggregator.aggregate(
                        List.of(
                                Severity.MEDIUM,
                                Severity.MEDIUM
                        )
                )
        );
    }

    @Test
    void shouldAggregateMediumAndHighToCritical() {
        assertEquals(
                RiskScore.CRITICAL,
                riskAggregator.aggregate(
                        List.of(
                                Severity.MEDIUM,
                                Severity.HIGH
                        )
                )
        );
    }

    @Test
    void shouldAggregateLowAndMediumToMedium() {
        assertEquals(
                RiskScore.HIGH,
                riskAggregator.aggregate(
                        List.of(
                                Severity.LOW,
                                Severity.MEDIUM
                        )
                )
        );
    }

    @Test
    void shouldCapAggregatedScoreAtCritical() {
        assertEquals(
                RiskScore.CRITICAL,
                riskAggregator.aggregate(
                        List.of(
                                Severity.CRITICAL,
                                Severity.CRITICAL
                        )
                )
        );
    }
}