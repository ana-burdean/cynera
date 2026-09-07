package com.cynera.backend.telemetry.network.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.event.dto.EventIngestionResponse;
import com.cynera.backend.telemetry.network.dto.NetworkTelemetry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NetworkTelemetryServiceTest {

    @Mock
    private AgentEventService agentEventService;

    @InjectMocks
    private NetworkTelemetryService networkTelemetryService;

    private static final String AGENT_TOKEN = "network-agent-token";

    private static final Instant TIMESTAMP =
            Instant.parse("2026-09-07T10:00:00Z");

    @Test
    void shouldMapNetworkTelemetryToNetworkConnectionEvent() {
        NetworkTelemetry telemetry = new NetworkTelemetry(
                "WIN-NET-01",
                "8.8.8.8",
                443,
                "TCP",
                "ana",
                "chrome.exe",
                "explorer.exe",
                TIMESTAMP
        );

        EventIngestionResponse response =
                new EventIngestionResponse(
                        1L,
                        "NETWORK_CONNECTION",
                        "WIN-NET-01",
                        TIMESTAMP
                );

        when(agentEventService.ingest(
                eq(AGENT_TOKEN),
                any(AgentEventRequest.class)
        )).thenReturn(response);

        EventIngestionResponse result =
                networkTelemetryService.ingest(
                        AGENT_TOKEN,
                        telemetry
                );

        assertEquals(response, result);

        ArgumentCaptor<AgentEventRequest> captor =
                ArgumentCaptor.forClass(AgentEventRequest.class);

        verify(agentEventService).ingest(
                eq(AGENT_TOKEN),
                captor.capture()
        );

        AgentEventRequest request = captor.getValue();

        assertEquals("NETWORK_CONNECTION", request.eventType());
        assertEquals("WIN-NET-01", request.hostname());
        assertEquals("ana", request.username());
        assertEquals("chrome.exe", request.processName());
        assertEquals("explorer.exe", request.parentProcessName());
        assertEquals(TIMESTAMP, request.timestamp());
        assertEquals("8.8.8.8", request.remoteAddress());
        assertEquals(443, request.remotePort());
        assertEquals("TCP", request.networkProtocol());
    }

    @Test
    void shouldUseCurrentTimestampWhenTimestampIsNull() {
        NetworkTelemetry telemetry = new NetworkTelemetry(
                "WIN-NET-01",
                "1.1.1.1",
                443,
                "TCP",
                "ana",
                "chrome.exe",
                "explorer.exe",
                null
        );

        networkTelemetryService.ingest(
                AGENT_TOKEN,
                telemetry
        );

        ArgumentCaptor<AgentEventRequest> captor =
                ArgumentCaptor.forClass(AgentEventRequest.class);

        verify(agentEventService).ingest(
                eq(AGENT_TOKEN),
                captor.capture()
        );

        AgentEventRequest request = captor.getValue();

        assertEquals(
                "NETWORK_CONNECTION",
                request.eventType()
        );

        assertEquals(
                "WIN-NET-01",
                request.hostname()
        );

        assertEquals(
                "ana",
                request.username()
        );

        assertEquals(
                "chrome.exe",
                request.processName()
        );

        assertEquals(
                "explorer.exe",
                request.parentProcessName()
        );

        assertEquals("1.1.1.1", request.remoteAddress());
        assertEquals(443, request.remotePort());
        assertEquals("TCP", request.networkProtocol());
    }

    @Test
    void shouldRejectNullTelemetry() {
        assertThrows(
                IllegalArgumentException.class,
                () -> networkTelemetryService.ingest(
                        AGENT_TOKEN,
                        null
                )
        );
    }

    @Test
    void shouldRejectMissingRemoteAddress() {
        NetworkTelemetry telemetry = new NetworkTelemetry(
                "WIN-NET-01",
                null,
                443,
                "TCP",
                "ana",
                "chrome.exe",
                "explorer.exe",
                TIMESTAMP
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> networkTelemetryService.ingest(
                        AGENT_TOKEN,
                        telemetry
                )
        );
    }

    @Test
    void shouldRejectBlankRemoteAddress() {
        NetworkTelemetry telemetry = new NetworkTelemetry(
                "WIN-NET-01",
                "   ",
                443,
                "TCP",
                "ana",
                "chrome.exe",
                "explorer.exe",
                TIMESTAMP
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> networkTelemetryService.ingest(
                        AGENT_TOKEN,
                        telemetry
                )
        );
    }
}
