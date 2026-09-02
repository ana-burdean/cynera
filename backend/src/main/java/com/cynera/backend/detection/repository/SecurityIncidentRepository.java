package com.cynera.backend.detection.repository;

import com.cynera.backend.detection.entity.SecurityIncident;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityIncidentRepository
        extends JpaRepository<SecurityIncident, Long> {
}