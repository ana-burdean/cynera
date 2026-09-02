package com.cynera.backend.detection.model;

public enum RiskScore {

    LOW(25),
    MEDIUM(50),
    HIGH(75),
    CRITICAL(100);

    private final int value;

    RiskScore(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }

    public static RiskScore fromSeverity(Severity severity) {
        return switch (severity) {
            case LOW -> LOW;
            case MEDIUM -> MEDIUM;
            case HIGH -> HIGH;
            case CRITICAL -> CRITICAL;
        };
    }
}