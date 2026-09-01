package com.cynera.backend.detection.controller;

import com.cynera.backend.detection.dto.DetectionResponse;
import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.detection.service.DetectionService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/detections")
public class DetectionController {

    private final DetectionService detectionService;

    public DetectionController(DetectionService detectionService) {
        this.detectionService = detectionService;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public DetectionResponse createDetection(
            @RequestParam Long eventId,
            @RequestParam String rule,
            @RequestParam Severity severity,
            @RequestParam String description
    ) {
        return detectionService.createDetection(
                eventId,
                rule,
                severity,
                description
        );
    }

    @GetMapping
    public List<DetectionResponse> getAllDetections() {
        return detectionService.getAllDetections();
    }
}
