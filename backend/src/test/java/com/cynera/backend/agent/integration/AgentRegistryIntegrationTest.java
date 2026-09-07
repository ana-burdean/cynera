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
class AgentRegistryIntegrationTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private AgentRepository agentRepository;
    @Autowired private SecurityEventRepository securityEventRepository;
    @Autowired private DetectionRepository detectionRepository;

    @BeforeEach
    void setUp() {
        detectionRepository.deleteAll();
        securityEventRepository.deleteAll();
        agentRepository.deleteAll();
        agentRepository.save(new Agent("registry-agent", "WIN-REG-01", "registry-token",
                true, Instant.parse("2026-09-07T09:00:00Z")));
    }

    @Test
    void shouldPersistRegistryTelemetry() throws Exception {
        mockMvc.perform(post("/api/v1/agent/registry")
                        .header("X-Agent-Token", "registry-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"hostname":"WIN-REG-01","registryPath":"HKCU\\\\Software\\\\Test",
                                 "registryAction":"MODIFIED","registryValueName":"Updater",
                                 "registryValueData":"powershell.exe","username":"ana",
                                 "processName":"reg.exe","timestamp":"2026-09-07T10:00:00Z"}
                                """))
                .andExpect(status().isCreated());

        SecurityEvent event = securityEventRepository.findAll().getFirst();
        assertEquals("REGISTRY_MODIFIED", event.getEventType());
        assertEquals("HKCU\\Software\\Test", event.getRegistryPath());
        assertEquals("MODIFIED", event.getRegistryAction());
        assertEquals("Updater", event.getRegistryValueName());
        assertEquals("powershell.exe", event.getRegistryValueData());
    }
}
