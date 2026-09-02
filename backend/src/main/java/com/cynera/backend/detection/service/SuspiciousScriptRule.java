package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

@Component
public class SuspiciousScriptRule implements DetectionRule {

    private static final String RULE_NAME = "SUSPICIOUS_SCRIPT";

    private static final String[] SCRIPT_EXTENSIONS = {
            ".ps1",
            ".bat",
            ".cmd",
            ".vbs",
            ".js"
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

        String processName = event.getProcessName().toLowerCase(Locale.ROOT);

        for (String extension : SCRIPT_EXTENSIONS) {
            if (processName.endsWith(extension)) {
                return Optional.of(
                        new DetectionMatch(
                                Severity.MEDIUM,
                                "Script execution detected"
                        )
                );
            }
        }

        return Optional.empty();
    }
}