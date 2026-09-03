package com.cynera.backend.agent.repository;

import com.cynera.backend.agent.entity.Agent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AgentRepository extends JpaRepository<Agent, Long> {

    Optional<Agent> findByAgentName(String agentName);

    boolean existsByAgentName(String agentName);

    Optional<Agent> findByAgentToken(String agentToken);
}