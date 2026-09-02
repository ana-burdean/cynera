package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

@Component
public class OfficeSpawnedShellRule implements DetectionRule {

    private static final String RULE_NAME = "OFFICE_SPAWNED_SHELL";

    private static final String[] OFFICE_PROCESSES = {
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe"
    };

    private static final String[] SHELL_PROCESSES = {
            "powershell.exe",
            "pwsh.exe",
            "cmd.exe",
            "cmd"
    };

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionMatch> evaluate(SecurityEvent event) {
        if (event.getProcessName() == null
                || event.getParentProcessName() == null) {
            return Optional.empty();
        }

        String processName =
                event.getProcessName().toLowerCase(Locale.ROOT);

        String parentProcessName =
                event.getParentProcessName().toLowerCase(Locale.ROOT);

        if (!isOfficeProcess(parentProcessName)) {
            return Optional.empty();
        }

        if (!isShellProcess(processName)) {
            return Optional.empty();
        }

        return Optional.of(
                new DetectionMatch(
                        Severity.HIGH,
                        "Office application spawned a command shell"
                )
        );
    }

    private boolean isOfficeProcess(String processName) {
        for (String officeProcess : OFFICE_PROCESSES) {
            if (processName.equals(officeProcess)) {
                return true;
            }
        }

        return false;
    }

    private boolean isShellProcess(String processName) {
        for (String shellProcess : SHELL_PROCESSES) {
            if (processName.equals(shellProcess)) {
                return true;
            }
        }

        return false;
    }
}