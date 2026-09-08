package com.cynera.backend.agent.dto;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class AgentCommandTest {

    @Test
    void shouldCreateKillProcessCommand() {
        String correlationId = UUID.randomUUID().toString();
        AgentCommand command = AgentCommand.killProcess("1234", "malware.exe", correlationId);

        assertEquals("KILL_PROCESS", command.commandType());
        assertEquals(correlationId, command.correlationId());
        assertNotNull(command.commandId());
        assertNotNull(command.timestamp());
        assertEquals("1234", command.parameters().get("processId"));
        assertEquals("malware.exe", command.parameters().get("processName"));
    }

    @Test
    void shouldCreateQuarantineFileCommand() {
        String correlationId = UUID.randomUUID().toString();
        AgentCommand command = AgentCommand.quarantineFile("C:\\temp\\malware.exe", "Ransomware detected", correlationId);

        assertEquals("QUARANTINE_FILE", command.commandType());
        assertEquals("C:\\temp\\malware.exe", command.parameters().get("filePath"));
        assertEquals("Ransomware detected", command.parameters().get("reason"));
    }

    @Test
    void shouldCreateIsolateEndpointCommand() {
        String correlationId = UUID.randomUUID().toString();
        AgentCommand command = AgentCommand.isolateEndpoint("WIN-HOST", "Critical threat", correlationId);

        assertEquals("ISOLATE_ENDPOINT", command.commandType());
        assertEquals("WIN-HOST", command.parameters().get("hostname"));
        assertEquals("Critical threat", command.parameters().get("reason"));
    }

    @Test
    void shouldCreateProtectFileCommand() {
        String correlationId = UUID.randomUUID().toString();
        AgentCommand command = AgentCommand.protectFile("C:\\Windows\\System32\\critical.dll", correlationId);

        assertEquals("PROTECT_FILE", command.commandType());
        assertEquals("C:\\Windows\\System32\\critical.dll", command.parameters().get("filePath"));
    }

    @Test
    void shouldCreateUnprotectFileCommand() {
        String correlationId = UUID.randomUUID().toString();
        AgentCommand command = AgentCommand.unprotectFile("C:\\temp\\test.txt", correlationId);

        assertEquals("UNPROTECT_FILE", command.commandType());
        assertEquals("C:\\temp\\test.txt", command.parameters().get("filePath"));
    }

    @Test
    void shouldHaveUniqueCommandIds() {
        AgentCommand cmd1 = AgentCommand.killProcess("1", "a.exe", "corr");
        AgentCommand cmd2 = AgentCommand.killProcess("2", "b.exe", "corr");

        assertNotEquals(cmd1.commandId(), cmd2.commandId());
    }
}