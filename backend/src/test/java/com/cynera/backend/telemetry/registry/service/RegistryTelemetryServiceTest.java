package com.cynera.backend.telemetry.registry.service;

import com.cynera.backend.agent.dto.AgentEventRequest;
import com.cynera.backend.agent.service.AgentEventService;
import com.cynera.backend.telemetry.registry.dto.RegistryTelemetry;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RegistryTelemetryServiceTest {

    private final AgentEventService agentEventService = mock(AgentEventService.class);
    private final RegistryTelemetryService registryTelemetryService =
            new RegistryTelemetryService(agentEventService);

    @Test
    void shouldMapRegistryModification() {
        RegistryTelemetry telemetry = new RegistryTelemetry(
                "WIN-REG-01", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "MODIFIED", "Updater", "powershell.exe -enc payload", "ana",
                "reg.exe", "cmd.exe", Instant.parse("2026-09-07T12:00:00Z"));

        when(agentEventService.ingest(eq("token"), any(AgentEventRequest.class)))
                .thenReturn(null);

        registryTelemetryService.ingest("token", telemetry);

        ArgumentCaptor<AgentEventRequest> captor =
                ArgumentCaptor.forClass(AgentEventRequest.class);
        verify(agentEventService).ingest(eq("token"), captor.capture());

        AgentEventRequest request = captor.getValue();
        assertEquals("REGISTRY_MODIFIED", request.eventType());
        assertEquals(telemetry.registryPath(), request.registryPath());
        assertEquals("MODIFIED", request.registryAction());
        assertEquals("Updater", request.registryValueName());
        assertEquals("powershell.exe -enc payload", request.registryValueData());
    }

    @Test
    void shouldRejectUnsupportedRegistryAction() {
        RegistryTelemetry telemetry = new RegistryTelemetry(
                "WIN-REG-01", "HKCU\\Software\\Test", "READ", null, null,
                null, null, null, null);

        assertThrows(IllegalArgumentException.class,
                () -> registryTelemetryService.ingest("token", telemetry));
    }
}
