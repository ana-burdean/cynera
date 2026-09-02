package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

@Component
public class KnownSuspiciousProcessRule implements DetectionRule {

    private static final String RULE_NAME = "KNOWN_SUSPICIOUS_PROCESS";

    private static final String[] SUSPICIOUS_PROCESSES = {
            "mimikatz.exe",
            "procdump.exe",
            "psexec.exe",
            "rubeus.exe",
            "cobaltstrike.exe"
    };

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionMatch> evaluate(SecurityEvent event) {
        if (event.getProcessName() == null) {
            return Optional.empty();
        }

        String processName =
                event.getProcessName().toLowerCase(Locale.ROOT);

        for (String suspiciousProcess : SUSPICIOUS_PROCESSES) {
            if (processName.equals(suspiciousProcess)) {
                return Optional.of(
                        new DetectionMatch(
                                Severity.HIGH,
                                "Known suspicious process detected"
                        )
                );
            }
        }

        return Optional.empty();
    }
}
