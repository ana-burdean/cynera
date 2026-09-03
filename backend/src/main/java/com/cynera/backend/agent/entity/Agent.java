package com.cynera.backend.agent.entity;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "agents")
public class Agent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String agentName;

    @Column(nullable = false)
    private String hostname;

    @Column(nullable = false)
    private String agentToken;

    @Column(nullable = false)
    private boolean enabled;

    @Column(nullable = false)
    private Instant registeredAt;

    protected Agent() {
    }

    public Agent(
            String agentName,
            String hostname,
            String agentToken,
            boolean enabled,
            Instant registeredAt
    ) {
        this.agentName = agentName;
        this.hostname = hostname;
        this.agentToken = agentToken;
        this.enabled = enabled;
        this.registeredAt = registeredAt;
    }

    public Long getId() {
        return id;
    }

    public String getAgentName() {
        return agentName;
    }

    public String getHostname() {
        return hostname;
    }

    public String getAgentToken() {
        return agentToken;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Instant getRegisteredAt() {
        return registeredAt;
    }
}