package com.cynera.backend.agent.dto;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AgentCommandResponseTest {

    @Test
    void shouldCreateSuccessResponse() {
        String commandId = "cmd-123";
        AgentCommandResponse response = AgentCommandResponse.success(
                commandId, "KILL_PROCESS", "Process terminated", Map.of("exitCode", 0)
        );

        assertEquals(commandId, response.commandId());
        assertEquals("KILL_PROCESS", response.commandType());
        assertTrue(response.success());
        assertEquals("Process terminated", response.message());
        assertEquals(0, response.details().get("exitCode"));
        assertNotNull(response.executedAt());
    }

    @Test
    void shouldCreateFailureResponse() {
        String commandId = "cmd-456";
        AgentCommandResponse response = AgentCommandResponse.failure(
                commandId, "QUARANTINE_FILE", "File not found"
        );

        assertEquals(commandId, response.commandId());
        assertEquals("QUARANTINE_FILE", response.commandType());
        assertFalse(response.success());
        assertEquals("File not found", response.message());
        assertTrue(response.details().isEmpty());
        assertNotNull(response.executedAt());
    }
}