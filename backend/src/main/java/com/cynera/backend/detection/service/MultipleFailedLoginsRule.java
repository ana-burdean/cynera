package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import com.cynera.backend.event.repository.SecurityEventRepository;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

@Component
public class MultipleFailedLoginsRule implements DetectionRule {

    private static final String RULE_NAME = "MULTIPLE_FAILED_LOGINS";

    private static final String FAILED_LOGIN_EVENT = "FAILED_LOGIN";

    private static final int FAILED_LOGIN_THRESHOLD = 3;

    private static final Duration TIME_WINDOW =
            Duration.ofMinutes(5);

    private final SecurityEventRepository securityEventRepository;

    public MultipleFailedLoginsRule(
            SecurityEventRepository securityEventRepository
    ) {
        this.securityEventRepository = securityEventRepository;
    }

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionMatch> evaluate(SecurityEvent event) {
        if (event.getEventType() == null
                || event.getUsername() == null
                || event.getHostname() == null
                || event.getTimestamp() == null) {
            return Optional.empty();
        }

        if (!FAILED_LOGIN_EVENT.equalsIgnoreCase(event.getEventType())) {
            return Optional.empty();
        }

        Instant windowStart =
                event.getTimestamp().minus(TIME_WINDOW);

        long failedLoginCount =
                securityEventRepository
                        .countByEventTypeAndUsernameAndHostnameAndTimestampAfter(
                                FAILED_LOGIN_EVENT,
                                event.getUsername(),
                                event.getHostname(),
                                windowStart
                        );

        if (failedLoginCount < FAILED_LOGIN_THRESHOLD) {
            return Optional.empty();
        }

        return Optional.of(
                new DetectionMatch(
                        Severity.HIGH,
                        "Multiple failed login attempts detected"
                )
        );
    }
}