package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

@Component
public class SuspiciousPowerShellRule implements DetectionRule {

    private static final String RULE_NAME = "SUSPICIOUS_POWERSHELL";

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

        if (!processName.equals("powershell.exe")
                && !processName.equals("pwsh.exe")) {
            return Optional.empty();
        }

        return Optional.of(
                new DetectionMatch(
                        Severity.MEDIUM,
                        "PowerShell execution detected"
                )
        );
    }
}
