package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

@Component
public class PrivilegeEscalationRule implements DetectionRule {

    private static final String RULE_NAME = "PRIVILEGE_ESCALATION";

    private static final String[] SUSPICIOUS_PROCESSES = {
            "runas.exe",
            "sudo.exe",
            "psexec.exe"
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
                                Severity.CRITICAL,
                                "Potential privilege escalation detected"
                        )
                );
            }
        }

        return Optional.empty();
    }
}
