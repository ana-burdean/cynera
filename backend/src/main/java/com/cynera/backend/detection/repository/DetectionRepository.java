package com.cynera.backend.detection.repository;

import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.model.Severity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DetectionRepository extends JpaRepository<Detection, Long> {

    Optional<Detection> findByEventIdAndRule(
            Long eventId,
            String rule
    );
}