package com.cynera.backend.detection.response.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;

@Entity
@Table(name = "response_actions")
public class ResponseAction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 36)
    private String actionId;

    @Column(nullable = false, length = 50)
    private String actionType;

    @Column(nullable = false, length = 100)
    private String targetIdentifier;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private java.util.Map<String, Object> parameters;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Status status = Status.PENDING;

    @Column(name = "incident_id")
    private Long incidentId;

    @Column(name = "detection_id")
    private Long detectionId;

    @Column(name = "triggered_by", length = 100)
    private String triggeredBy;

    @Column(nullable = false)
    private Instant createdAt;

    private Instant startedAt;
    private Instant completedAt;

    @Column(length = 2000)
    private String resultMessage;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private java.util.Map<String, Object> resultDetails;

    @Column(length = 20)
    private String agentToken;

    @Column(name = "correlation_id", length = 36)
    private String correlationId;

    protected ResponseAction() {}

    public ResponseAction(String actionId, String actionType, String targetIdentifier,
                          java.util.Map<String, Object> parameters, Long incidentId,
                          Long detectionId, String triggeredBy, String agentToken, String correlationId) {
        this.actionId = actionId;
        this.actionType = actionType;
        this.targetIdentifier = targetIdentifier;
        this.parameters = parameters;
        this.incidentId = incidentId;
        this.detectionId = detectionId;
        this.triggeredBy = triggeredBy;
        this.agentToken = agentToken;
        this.correlationId = correlationId;
        this.createdAt = Instant.now();
    }

    public Long getId() { return id; }
    public String getActionId() { return actionId; }
    public String getActionType() { return actionType; }
    public String getTargetIdentifier() { return targetIdentifier; }
    public java.util.Map<String, Object> getParameters() { return parameters; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public Long getIncidentId() { return incidentId; }
    public Long getDetectionId() { return detectionId; }
    public String getTriggeredBy() { return triggeredBy; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }
    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }
    public String getResultMessage() { return resultMessage; }
    public void setResultMessage(String resultMessage) { this.resultMessage = resultMessage; }
    public java.util.Map<String, Object> getResultDetails() { return resultDetails; }
    public void setResultDetails(java.util.Map<String, Object> resultDetails) { this.resultDetails = resultDetails; }
    public String getAgentToken() { return agentToken; }
    public String getCorrelationId() { return correlationId; }

    public enum Status {
        PENDING, EXECUTING, COMPLETED, FAILED, CANCELLED, TIMEOUT
    }
}