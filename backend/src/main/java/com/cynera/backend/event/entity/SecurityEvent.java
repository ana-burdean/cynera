package com.cynera.backend.event.entity;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Instant timestamp;

    @Column(nullable = false)
    private String eventType;

    @Column(nullable = false)
    private String hostname;

    private String username;

    private String processName;

    private String parentProcessName;

    protected SecurityEvent() {
    }

    public SecurityEvent(
            Instant timestamp,
            String eventType,
            String hostname,
            String username,
            String processName,
            String parentProcessName
    ) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.hostname = hostname;
        this.username = username;
        this.processName = processName;
        this.parentProcessName = parentProcessName;
    }

    public Long getId() {
        return id;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getEventType() {
        return eventType;
    }

    public String getHostname() {
        return hostname;
    }

    public String getUsername() {
        return username;
    }

    public String getProcessName() {
        return processName;
    }

    public String getParentProcessName() {
        return parentProcessName;
    }
}
