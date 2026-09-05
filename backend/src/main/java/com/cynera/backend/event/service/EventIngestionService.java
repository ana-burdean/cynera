package com.cynera.backend.event.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.event.dto.EventRequest;
import com.cynera.backend.event.dto.EventResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class EventIngestionService {

    private final EventService eventService;
    private final EventIngestionMapper eventIngestionMapper;

    public EventIngestionService(
            EventService eventService,
            EventIngestionMapper eventIngestionMapper
    ) {
        this.eventService = eventService;
        this.eventIngestionMapper = eventIngestionMapper;
    }

    @Transactional
    public EventIngestionResponse ingest(
            AgentEventRequest request
    ) {
        EventRequest eventRequest =
                eventIngestionMapper.toEventRequest(request);

        EventResponse eventResponse =
                eventService.ingestEvent(eventRequest);

        return eventIngestionMapper.toIngestionResponse(
                eventResponse
        );
    }
}