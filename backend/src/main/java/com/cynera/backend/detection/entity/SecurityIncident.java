package com.cynera.backend.detection.entity;

import com.cynera.backend.detection.model.RiskScore;
import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "security_incidents")
public class SecurityIncident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String hostname;

    private String username;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RiskScore riskScore;

    @Column(nullable = false)
    private Instant createdAt;

    protected SecurityIncident() {
    }

    public SecurityIncident(
            String hostname,
            String username,
            RiskScore riskScore,
            Instant createdAt
    ) {
        this.hostname = hostname;
        this.username = username;
        this.riskScore = riskScore;
        this.createdAt = createdAt;
    }

    public Long getId() {
        return id;
    }

    public String getHostname() {
        return hostname;
    }

    public String getUsername() {
        return username;
    }

    public RiskScore getRiskScore() {
        return riskScore;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}