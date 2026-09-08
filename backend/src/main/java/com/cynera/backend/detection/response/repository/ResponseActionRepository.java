package com.cynera.backend.detection.response.repository;
import com.cynera.backend.detection.response.entity.ResponseAction;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface ResponseActionRepository extends JpaRepository<ResponseAction, Long> {

    List<ResponseAction> findByIncidentId(Long incidentId);

    List<ResponseAction> findByDetectionId(Long detectionId);

    List<ResponseAction> findByStatus(ResponseAction.Status status);

    List<ResponseAction> findByAgentToken(String agentToken);

    Optional<ResponseAction> findByActionId(String actionId);

    @Query("SELECT r FROM ResponseAction r WHERE r.status IN :statuses AND r.createdAt < :cutoff")
    List<ResponseAction> findStaleActions(List<ResponseAction.Status> statuses, Instant cutoff);

    long countByIncidentId(Long incidentId);

    long countByStatus(ResponseAction.Status status);
}