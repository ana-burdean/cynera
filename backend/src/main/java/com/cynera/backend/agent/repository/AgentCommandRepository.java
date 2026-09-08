package com.cynera.backend.agent.repository;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.entity.AgentCommandEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AgentCommandRepository extends JpaRepository<AgentCommandEntity, String> {

    List<AgentCommandEntity> findByAgentAndStatusOrderByCreatedAtAsc(Agent agent, AgentCommandEntity.Status status);

    Optional<AgentCommandEntity> findByCommandIdAndAgent(String commandId, Agent agent);

    @Query("SELECT c FROM AgentCommandEntity c WHERE c.agent = :agent AND c.status = :status AND c.createdAt < :cutoff")
    List<AgentCommandEntity> findExpiredCommands(Agent agent, AgentCommandEntity.Status status, java.time.Instant cutoff);

    long countByAgentAndStatus(Agent agent, AgentCommandEntity.Status status);
}