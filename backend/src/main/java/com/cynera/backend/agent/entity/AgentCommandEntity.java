package com.cynera.backend.agent.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.Map;

@Entity
@Table(name = "agent_commands")
public class AgentCommandEntity {

    public enum Status {
        PENDING, SENT, COMPLETED, FAILED, EXPIRED
    }

    @Id
    @Column(name = "command_id", nullable = false, length = 36)
    private String commandId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "agent_id", nullable = false)
    private Agent agent;

    @Column(name = "command_type", nullable = false, length = 50)
    private String commandType;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "parameters", columnDefinition = "jsonb")
    private Map<String, Object> parameters;

    @Column(name = "correlation_id", length = 36)
    private String correlationId;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private Status status = Status.PENDING;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "sent_at")
    private Instant sentAt;

    @Column(name = "executed_at")
    private Instant executedAt;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "result_message", length = 1000)
    private String resultMessage;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "result_details", columnDefinition = "jsonb")
    private Map<String, Object> resultDetails;

    protected AgentCommandEntity() {
    }

    public AgentCommandEntity(String commandId, Agent agent, String commandType,
                              Map<String, Object> parameters, String correlationId, Instant createdAt) {
        this.commandId = commandId;
        this.agent = agent;
        this.commandType = commandType;
        this.parameters = parameters;
        this.correlationId = correlationId;
        this.createdAt = createdAt;
    }

    public String getCommandId() { return commandId; }
    public void setCommandId(String commandId) { this.commandId = commandId; }

    public Agent getAgent() { return agent; }
    public void setAgent(Agent agent) { this.agent = agent; }

    public String getCommandType() { return commandType; }
    public void setCommandType(String commandType) { this.commandType = commandType; }

    public Map<String, Object> getParameters() { return parameters; }
    public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }

    public String getCorrelationId() { return correlationId; }
    public void setCorrelationId(String correlationId) { this.correlationId = correlationId; }

    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getSentAt() { return sentAt; }
    public void setSentAt(Instant sentAt) { this.sentAt = sentAt; }

    public Instant getExecutedAt() { return executedAt; }
    public void setExecutedAt(Instant executedAt) { this.executedAt = executedAt; }

    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }

    public String getResultMessage() { return resultMessage; }
    public void setResultMessage(String resultMessage) { this.resultMessage = resultMessage; }

    public Map<String, Object> getResultDetails() { return resultDetails; }
    public void setResultDetails(Map<String, Object> resultDetails) { this.resultDetails = resultDetails; }
}