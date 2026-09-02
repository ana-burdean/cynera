package com.cynera.backend.detection.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RiskScoreTest {

    @Test
    void shouldMapLowSeverityTo25() {
        assertEquals(
                25,
                RiskScore.fromSeverity(Severity.LOW).getValue()
        );
    }

    @Test
    void shouldMapMediumSeverityTo50() {
        assertEquals(
                50,
                RiskScore.fromSeverity(Severity.MEDIUM).getValue()
        );
    }

    @Test
    void shouldMapHighSeverityTo75() {
        assertEquals(
                75,
                RiskScore.fromSeverity(Severity.HIGH).getValue()
        );
    }

    @Test
    void shouldMapCriticalSeverityTo100() {
        assertEquals(
                100,
                RiskScore.fromSeverity(Severity.CRITICAL).getValue()
        );
    }
}