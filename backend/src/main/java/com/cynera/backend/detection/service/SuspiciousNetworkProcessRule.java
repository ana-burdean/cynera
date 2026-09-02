package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

@Component
public class SuspiciousNetworkProcessRule implements DetectionRule {

    private static final String RULE_NAME = "SUSPICIOUS_NETWORK_PROCESS";

    private static final String[] NETWORK_PROCESSES = {
            "curl.exe",
            "curl",
            "wget.exe",
            "wget",
            "certutil.exe",
            "bitsadmin.exe"
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

        for (String networkProcess : NETWORK_PROCESSES) {
            if (processName.equals(networkProcess)) {
                return Optional.of(
                        new DetectionMatch(
                                Severity.HIGH,
                                "Suspicious network-capable process detected"
                        )
                );
            }
        }

        return Optional.empty();
    }
}
