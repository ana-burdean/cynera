package com.cynera.backend.health.dto;

public record HealthResponse(
        String status,
        String service,
        String version
) {
}
