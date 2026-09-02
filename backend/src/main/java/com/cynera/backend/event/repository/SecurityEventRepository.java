package com.cynera.backend.event.repository;

import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface SecurityEventRepository
        extends JpaRepository<SecurityEvent, Long> {

    long countByEventTypeAndUsernameAndHostnameAndTimestampAfter(
            String eventType,
            String username,
            String hostname,
            Instant timestamp
    );
}