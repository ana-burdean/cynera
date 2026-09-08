package com.cynera.backend.detection.response.entity;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ResponseActionTest {

    @Test
    void shouldCreateResponseAction() {
        ResponseAction action = new ResponseAction(
                "action-123", "KILL_PROCESS", "malware.exe",
                Map.of("processId", "1234"),
                1L, 2L, "user", "agent-token", "corr-1"
        );

        assertEquals("action-123", action.getActionId());
        assertEquals("KILL_PROCESS", action.getActionType());
        assertEquals("malware.exe", action.getTargetIdentifier());
        assertEquals(1L, action.getIncidentId());
        assertEquals(2L, action.getDetectionId());
        assertEquals("user", action.getTriggeredBy());
        assertEquals("agent-token", action.getAgentToken());
        assertEquals("corr-1", action.getCorrelationId());
        assertEquals(ResponseAction.Status.PENDING, action.getStatus());
        assertNotNull(action.getCreatedAt());
    }

    @Test
    void shouldUpdateStatus() {
        ResponseAction action = new ResponseAction(
                "action-123", "KILL_PROCESS", "malware.exe",
                Map.of(), 1L, 2L, "user", "agent-token", "corr-1"
        );

        action.setStatus(ResponseAction.Status.EXECUTING);
        action.setStartedAt(Instant.now());
        assertEquals(ResponseAction.Status.EXECUTING, action.getStatus());

        action.setStatus(ResponseAction.Status.COMPLETED);
        action.setCompletedAt(Instant.now());
        action.setResultMessage("Success");
        assertEquals(ResponseAction.Status.COMPLETED, action.getStatus());
        assertEquals("Success", action.getResultMessage());
    }

    @Test
    void shouldHaveAllStatusValues() {
        ResponseAction.Status[] statuses = ResponseAction.Status.values();
        assertEquals(6, statuses.length);
        assertTrue(contains(statuses, ResponseAction.Status.PENDING));
        assertTrue(contains(statuses, ResponseAction.Status.EXECUTING));
        assertTrue(contains(statuses, ResponseAction.Status.COMPLETED));
        assertTrue(contains(statuses, ResponseAction.Status.FAILED));
        assertTrue(contains(statuses, ResponseAction.Status.CANCELLED));
        assertTrue(contains(statuses, ResponseAction.Status.TIMEOUT));
    }

    private boolean contains(ResponseAction.Status[] array, ResponseAction.Status value) {
        for (ResponseAction.Status s : array) {
            if (s == value) return true;
        }
        return false;
    }
}