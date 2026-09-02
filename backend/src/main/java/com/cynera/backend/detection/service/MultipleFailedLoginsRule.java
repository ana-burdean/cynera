package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

@Component
public class MultipleFailedLoginsRule implements DetectionRule {

    private static final String RULE_NAME = "MULTIPLE_FAILED_LOGINS";

    private static final String FAILED_LOGIN_EVENT = "FAILED_LOGIN";

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionMatch> evaluate(SecurityEvent event) {
        if (event.getEventType() == null) {
            return Optional.empty();
        }

        String eventType =
                event.getEventType().toLowerCase(Locale.ROOT);

        if (!eventType.equals(FAILED_LOGIN_EVENT.toLowerCase(Locale.ROOT))) {
            return Optional.empty();
        }

        return Optional.of(
                new DetectionMatch(
                        Severity.HIGH,
                        "Failed login attempt detected"
                )
        );
    }
}
