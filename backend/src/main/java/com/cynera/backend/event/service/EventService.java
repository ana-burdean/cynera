package com.cynera.backend.event.service;

import com.cynera.backend.event.dto.EventRequest;
import com.cynera.backend.event.dto.EventResponse;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
public class EventService {

    private final SecurityEventRepository securityEventRepository;

    public EventService(SecurityEventRepository securityEventRepository) {
        this.securityEventRepository = securityEventRepository;
    }

    @Transactional
    public EventResponse ingestEvent(EventRequest request) {
        SecurityEvent event = new SecurityEvent(
                request.timestamp(),
                request.eventType(),
                request.hostname(),
                request.username(),
                request.processName(),
                request.parentProcessName()
        );

        SecurityEvent savedEvent = securityEventRepository.save(event);

        return EventResponse.from(savedEvent);
    }

    @Transactional(readOnly = true)
    public List<EventResponse> getAllEvents() {
        return securityEventRepository.findAll()
                .stream()
                .map(EventResponse::from)
                .toList();
    }
}