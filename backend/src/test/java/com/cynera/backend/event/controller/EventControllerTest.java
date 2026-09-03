package com.cynera.backend.event.controller;

import com.cynera.backend.event.dto.EventRequest;
import com.cynera.backend.event.dto.EventResponse;
import com.cynera.backend.event.service.EventService;
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
class EventControllerTest {

    @Mock
    private EventService eventService;

    @Test
    void shouldIngestEvent() throws Exception {
        EventResponse response = new EventResponse(
                1L,
                Instant.parse("2026-09-01T12:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "powershell.exe",
                "explorer.exe"
        );

        when(eventService.ingestEvent(
                new EventRequest(
                        Instant.parse("2026-09-01T12:00:00Z"),
                        "PROCESS_CREATED",
                        "DESKTOP-01",
                        "ana",
                        "powershell.exe",
                        "explorer.exe"
                )
        )).thenReturn(response);

        MockMvc mockMvc = MockMvcBuilders
                .standaloneSetup(new EventController(eventService))
                .build();

        mockMvc.perform(
                        post("/api/v1/events")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                                        {
                                          "timestamp": "2026-09-01T12:00:00Z",
                                          "eventType": "PROCESS_CREATED",
                                          "hostname": "DESKTOP-01",
                                          "username": "ana",
                                          "processName": "powershell.exe",
                                          "parentProcessName": "explorer.exe"
                                        }
                                        """)
                )
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(1))
                .andExpect(jsonPath("$.eventType")
                        .value("PROCESS_CREATED"))
                .andExpect(jsonPath("$.hostname")
                        .value("DESKTOP-01"))
                .andExpect(jsonPath("$.username")
                        .value("ana"))
                .andExpect(jsonPath("$.processName")
                        .value("powershell.exe"))
                .andExpect(jsonPath("$.parentProcessName")
                        .value("explorer.exe"));

        verify(eventService).ingestEvent(
                new EventRequest(
                        Instant.parse("2026-09-01T12:00:00Z"),
                        "PROCESS_CREATED",
                        "DESKTOP-01",
                        "ana",
                        "powershell.exe",
                        "explorer.exe"
                )
        );
    }

    @Test
    void shouldGetAllEvents() throws Exception {
        EventResponse response = new EventResponse(
                1L,
                Instant.parse("2026-09-01T12:00:00Z"),
                "PROCESS_CREATED",
                "DESKTOP-01",
                "ana",
                "cmd.exe",
                "explorer.exe"
        );

        when(eventService.getAllEvents())
                .thenReturn(List.of(response));

        MockMvc mockMvc = MockMvcBuilders
                .standaloneSetup(new EventController(eventService))
                .build();

        mockMvc.perform(
                        get("/api/v1/events")
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(1))
                .andExpect(jsonPath("$[0].id").value(1))
                .andExpect(jsonPath("$[0].eventType")
                        .value("PROCESS_CREATED"))
                .andExpect(jsonPath("$[0].hostname")
                        .value("DESKTOP-01"))
                .andExpect(jsonPath("$[0].processName")
                        .value("cmd.exe"));

        verify(eventService).getAllEvents();
    }
}