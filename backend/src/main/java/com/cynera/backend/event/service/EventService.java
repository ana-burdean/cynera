package com.cynera.backend.event.service;

import com.cynera.backend.detection.service.DetectionService;
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
    private final DetectionService detectionService;

    public EventService(
            SecurityEventRepository securityEventRepository,
            DetectionService detectionService
    ) {
        this.securityEventRepository = securityEventRepository;
        this.detectionService = detectionService;
    }

    @Transactional
    public EventResponse ingestEvent(EventRequest request) {

        SecurityEvent event = new SecurityEvent(
                request.timestamp(),
                request.eventType(),
                request.hostname(),
                request.username(),
                request.processName(),
                request.parentProcessName(),
                request.filePath(),
                request.fileAction(),
                request.fileSize(),
                request.fileHash(),
                request.remoteAddress(),
                request.remotePort(),
                request.networkProtocol(),
                request.registryPath(),
                request.registryAction(),
                request.registryValueName(),
                request.registryValueData(),
                request.windowsEventChannel(),
                request.windowsEventId(),
                request.windowsEventProvider(),
                request.windowsEventMessage()
        );

        SecurityEvent savedEvent = securityEventRepository.save(event);

        detectionService.evaluateEvent(savedEvent);

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
