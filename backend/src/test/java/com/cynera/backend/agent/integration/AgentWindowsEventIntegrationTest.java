package com.cynera.backend.agent.integration;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.repository.AgentRepository;
import com.cynera.backend.detection.repository.DetectionRepository;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AgentWindowsEventIntegrationTest {
    @Autowired private MockMvc mockMvc;
    @Autowired private AgentRepository agentRepository;
    @Autowired private SecurityEventRepository securityEventRepository;
    @Autowired private DetectionRepository detectionRepository;

    @BeforeEach
    void setUp() {
        detectionRepository.deleteAll(); securityEventRepository.deleteAll(); agentRepository.deleteAll();
        agentRepository.save(new Agent("windows-agent", "WIN-EVT-01", "windows-token", true, Instant.now()));
    }

    @Test
    void shouldPersistWindowsEvent() throws Exception {
        mockMvc.perform(post("/api/v1/agent/windows-events")
                        .header("X-Agent-Token", "windows-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"hostname":"WIN-EVT-01","channel":"Security","eventId":4625,
                                "provider":"Microsoft-Windows-Security-Auditing","message":"Failed logon",
                                "username":"ana","timestamp":"2026-09-07T10:00:00Z"}"""))
                .andExpect(status().isCreated());
        SecurityEvent event = securityEventRepository.findAll().getFirst();
        assertEquals("WINDOWS_EVENT", event.getEventType());
        assertEquals("Security", event.getWindowsEventChannel());
        assertEquals(4625, event.getWindowsEventId());
        assertEquals("Microsoft-Windows-Security-Auditing", event.getWindowsEventProvider());
        assertEquals("Failed logon", event.getWindowsEventMessage());
    }
}
