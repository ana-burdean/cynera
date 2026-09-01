package com.cynera.backend.detection.entity;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(
        name = "detections",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_detection_event_rule",
                        columnNames = {"event_id", "rule"}
                )
        }
)
public class Detection {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "event_id", nullable = false)
    private SecurityEvent event;

    @Column(nullable = false)
    private String rule;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Column(nullable = false, length = 1000)
    private String description;

    @Column(nullable = false)
    private Instant detectedAt;

    protected Detection() {
    }

    public Detection(
            SecurityEvent event,
            String rule,
            Severity severity,
            String description,
            Instant detectedAt
    ) {
        this.event = event;
        this.rule = rule;
        this.severity = severity;
        this.description = description;
        this.detectedAt = detectedAt;
    }

    public Long getId() {
        return id;
    }

    public SecurityEvent getEvent() {
        return event;
    }

    public String getRule() {
        return rule;
    }

    public Severity getSeverity() {
        return severity;
    }

    public String getDescription() {
        return description;
    }

    public Instant getDetectedAt() {
        return detectedAt;
    }
}