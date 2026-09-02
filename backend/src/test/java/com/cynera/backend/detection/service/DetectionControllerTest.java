package com.cynera.backend.detection.controller;

import com.cynera.backend.detection.dto.DetectionResponse;
import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.detection.service.DetectionService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;
import java.util.List;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class DetectionControllerTest {

    @Mock
    private DetectionService detectionService;

    @Test
    void shouldCreateDetection() throws Exception {
        DetectionResponse response = new DetectionResponse(
                1L,
                10L,
                "SUSPICIOUS_POWERSHELL",
                Severity.MEDIUM,
                "PowerShell execution detected",
                Instant.parse("2026-09-01T12:00:00Z")
        );

        when(detectionService.createDetection(
                10L,
                "SUSPICIOUS_POWERSHELL",
                Severity.MEDIUM,
                "PowerShell execution detected"
        )).thenReturn(response);

        MockMvc mockMvc = MockMvcBuilders
                .standaloneSetup(
                        new DetectionController(detectionService)
                )
                .build();

        mockMvc.perform(
                        post("/api/v1/detections")
                                .param("eventId", "10")
                                .param(
                                        "rule",
                                        "SUSPICIOUS_POWERSHELL"
                                )
                                .param("severity", "MEDIUM")
                                .param(
                                        "description",
                                        "PowerShell execution detected"
                                )
                                .contentType(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.eventId").value(10))
                .andExpect(jsonPath("$.rule")
                        .value("SUSPICIOUS_POWERSHELL"))
                .andExpect(jsonPath("$.severity").value("MEDIUM"))
                .andExpect(jsonPath("$.description")
                        .value("PowerShell execution detected"))
                .andExpect(jsonPath("$.detectedAt")
                        .value("2026-09-01T12:00:00Z"));

        verify(detectionService).createDetection(
                10L,
                "SUSPICIOUS_POWERSHELL",
                Severity.MEDIUM,
                "PowerShell execution detected"
        );
    }

    @Test
    void shouldGetAllDetections() throws Exception {
        DetectionResponse response = new DetectionResponse(
                1L,
                10L,
                "SUSPICIOUS_CMD",
                Severity.HIGH,
                "Command shell execution detected",
                Instant.parse("2026-09-01T12:00:00Z")
        );

        when(detectionService.getAllDetections())
                .thenReturn(List.of(response));

        MockMvc mockMvc = MockMvcBuilders
                .standaloneSetup(
                        new DetectionController(detectionService)
                )
                .build();

        mockMvc.perform(
                        get("/api/v1/detections")
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].eventId").value(10))
                .andExpect(jsonPath("$[0].rule")
                        .value("SUSPICIOUS_CMD"))
                .andExpect(jsonPath("$[0].severity").value("HIGH"))
                .andExpect(jsonPath("$[0].description")
                        .value("Command shell execution detected"));

        verify(detectionService).getAllDetections();
    }
}