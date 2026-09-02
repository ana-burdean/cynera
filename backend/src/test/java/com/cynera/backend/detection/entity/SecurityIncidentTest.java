package com.cynera.backend.detection.entity;

import com.cynera.backend.detection.model.RiskScore;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SecurityIncidentTest {

    @Test
    void shouldCreateSecurityIncident() {
        Instant createdAt =
                Instant.parse("2026-09-02T10:00:00Z");

        SecurityIncident incident = new SecurityIncident(
                "DESKTOP-01",
                "ana",
                RiskScore.CRITICAL,
                createdAt
        );

        assertEquals(
                "DESKTOP-01",
                incident.getHostname()
        );

        assertEquals(
                "ana",
                incident.getUsername()
        );

        assertEquals(
                RiskScore.CRITICAL,
                incident.getRiskScore()
        );

        assertEquals(
                createdAt,
                incident.getCreatedAt()
        );
    }

    @Test
    void shouldAllowNullUsername() {
        SecurityIncident incident = new SecurityIncident(
                "DESKTOP-01",
                null,
                RiskScore.HIGH,
                Instant.parse("2026-09-02T10:00:00Z")
        );

        assertEquals(
                "DESKTOP-01",
                incident.getHostname()
        );

        assertEquals(
                null,
                incident.getUsername()
        );

        assertEquals(
                RiskScore.HIGH,
                incident.getRiskScore()
        );
    }
}