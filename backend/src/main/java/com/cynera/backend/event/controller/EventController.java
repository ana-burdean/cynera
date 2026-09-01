package com.cynera.backend.event.controller;

import com.cynera.backend.event.dto.EventRequest;
import com.cynera.backend.event.dto.EventResponse;
import com.cynera.backend.event.service.EventService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/events")
public class EventController {

    private final EventService eventService;

    public EventController(EventService eventService) {
        this.eventService = eventService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public EventResponse ingestEvent(@Valid @RequestBody EventRequest request) {
        return eventService.ingestEvent(request);
    }

    @GetMapping
    public List<EventResponse> getAllEvents() {
        return eventService.getAllEvents();
    }
}