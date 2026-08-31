package com.cynera.backend.service;

import com.cynera.backend.dto.HealthResponse;
import org.springframework.stereotype.Service;

@Service
public class HealthService {

    private static final String SERVICE_NAME = "cynera-backend";
    private static final String VERSION = "0.1.0";

    public HealthResponse getHealth() {
        return new HealthResponse(
                "UP",
                SERVICE_NAME,
                VERSION
        );
    }
}