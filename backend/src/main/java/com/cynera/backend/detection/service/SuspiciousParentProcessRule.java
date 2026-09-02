package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

@Component
public class SuspiciousParentProcessRule implements DetectionRule {

    private static final String RULE_NAME = "SUSPICIOUS_PARENT_PROCESS";

    private static final String[] SUSPICIOUS_PARENTS = {
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe",
            "w3wp.exe",
            "sqlservr.exe"
    };

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionMatch> evaluate(SecurityEvent event) {
        if (event.getParentProcessName() == null) {
            return Optional.empty();
        }

        String parentProcessName =
                event.getParentProcessName().toLowerCase(Locale.ROOT);

        for (String suspiciousParent : SUSPICIOUS_PARENTS) {
            if (parentProcessName.equals(suspiciousParent)) {
                return Optional.of(
                        new DetectionMatch(
                                Severity.HIGH,
                                "Suspicious parent process detected"
                        )
                );
            }
        }

        return Optional.empty();
    }
}
