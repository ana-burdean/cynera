package com.cynera.backend.agent.controller;

import com.cynera.backend.agent.service.AgentService;
import com.cynera.backend.auth.security.JwtService;
import com.cynera.backend.auth.service.UserService;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.network.dto.NetworkTelemetry;
import com.cynera.backend.telemetry.network.service.NetworkTelemetryService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AgentNetworkController.class)
@AutoConfigureMockMvc(addFilters = false)
class AgentNetworkControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private NetworkTelemetryService networkTelemetryService;

    @MockitoBean
    private AgentService agentService;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private UserService userService;

    @Test
    void shouldAcceptNetworkTelemetry() throws Exception {
        EventIngestionResponse response =
                new EventIngestionResponse(
                        1L,
                        "NETWORK_CONNECTION",
                        "WIN-NET-01",
                        Instant.parse("2026-09-07T10:00:00Z")
                );

        when(networkTelemetryService.ingest(eq("network-agent-token"), any(NetworkTelemetry.class)))
                .thenReturn(response);

        String request = """
                {
                  "hostname": "WIN-NET-01",
                  "remoteAddress": "192.168.1.100",
                  "remotePort": 443,
                  "protocol": "TCP",
                  "username": "ana",
                  "processName": "powershell.exe",
                  "parentProcessName": "explorer.exe",
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/network")
                                .header("X-Agent-Token", "network-agent-token")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.eventType").value("NETWORK_CONNECTION"))
                .andExpect(jsonPath("$.hostname").value("WIN-NET-01"));

        verify(networkTelemetryService)
                .ingest(eq("network-agent-token"), any(NetworkTelemetry.class));
    }

    @Test
    void shouldRejectInvalidRequest() throws Exception {
        String request = """
                {
                  "hostname": "",
                  "remoteAddress": "192.168.1.100",
                  "remotePort": 443,
                  "protocol": "TCP",
                  "username": "ana",
                  "processName": "powershell.exe",
                  "parentProcessName": "explorer.exe",
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/network")
                                .header("X-Agent-Token", "network-agent-token")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldRequireAgentTokenHeader() throws Exception {
        String request = """
                {
                  "hostname": "WIN-NET-01",
                  "remoteAddress": "192.168.1.100",
                  "remotePort": 443,
                  "protocol": "TCP",
                  "username": "ana",
                  "processName": "powershell.exe",
                  "parentProcessName": "explorer.exe",
                  "timestamp": "2026-09-07T10:00:00Z"
                }
                """;

        mockMvc.perform(
                        post("/api/v1/agent/network")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isBadRequest());
    }
}
