package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

@Component
public class ProcessAnomalyRule implements DetectionRule {

    private static final String RULE_NAME = "PROCESS_ANOMALY";

    /*
     * Windows LOLBINs commonly abused to execute code, scripts,
     * DLLs or other payloads.
     */
    private static final Set<String> LOLBINS = Set.of(
            "mshta.exe",
            "rundll32.exe",
            "regsvr32.exe",
            "regasm.exe",
            "regsvcs.exe",
            "msiexec.exe",
            "installutil.exe",
            "cmstp.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "msbuild.exe",
            "wmic.exe",
            "wscript.exe",
            "cscript.exe",
            "csc.exe",
            "vbc.exe",
            "jsc.exe"
    );

    /*
     * Processes that normally belong to the Windows system/process
     * hierarchy. explorer.exe is intentionally NOT included here:
     * explorer.exe is a normal user-session process and is a legitimate
     * parent for many applications.
     */
    private static final Set<String> SYSTEM_PROCESSES = Set.of(
            "lsass.exe",
            "csrss.exe",
            "wininit.exe",
            "services.exe",
            "smss.exe",
            "winlogon.exe",
            "spoolsv.exe",
            "taskhost.exe",
            "dwm.exe",
            "svchost.exe",
            "dllhost.exe"
    );

    private static final Set<String> OFFICE_PROCESSES = Set.of(
            "winword.exe",
            "excel.exe",
            "powerpnt.exe",
            "outlook.exe"
    );

    private static final Set<String> SHELL_PROCESSES = Set.of(
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe"
    );

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionMatch> evaluate(SecurityEvent event) {
        if (event == null || event.getProcessName() == null) {
            return Optional.empty();
        }

        String processName = normalize(event.getProcessName());
        String parentProcessName = normalize(event.getParentProcessName());

        /*
         * LOLBIN execution is suspicious regardless of the parent process.
         */
        if (LOLBINS.contains(processName)) {
            return Optional.of(
                    new DetectionMatch(
                            Severity.HIGH,
                            "Suspicious LOLBIN execution detected"
                    )
            );
        }

        /*
         * Applications such as Office or Adobe Reader spawning a shell
         * are highly suspicious.
         */
        if (isSuspiciousParentChildRelationship(processName, parentProcessName)) {
            return Optional.of(
                    new DetectionMatch(
                            Severity.HIGH,
                            "Anomalous process parent relationship detected"
                    )
            );
        }

        /*
         * Detect unexpected parents for genuine Windows system processes.
         */
        if (isSystemProcessAnomaly(processName, parentProcessName)) {
            return Optional.of(
                    new DetectionMatch(
                            Severity.HIGH,
                            "Anomalous process parent relationship detected"
                    )
            );
        }

        return Optional.empty();
    }

    private boolean isSuspiciousParentChildRelationship(
            String processName,
            String parentProcessName
    ) {
        if (parentProcessName.isBlank()) {
            return false;
        }

        /*
         * Office -> shell is a classic execution chain.
         */
        if (OFFICE_PROCESSES.contains(parentProcessName)
                && SHELL_PROCESSES.contains(processName)) {
            return true;
        }

        /*
         * Other user applications spawning cmd/powershell are also
         * suspicious. This covers applications such as Adobe Reader.
         *
         * We deliberately exclude explorer.exe because:
         * explorer.exe -> cmd.exe
         * explorer.exe -> powershell.exe
         *
         * can be completely legitimate user activity.
         */
        if (SHELL_PROCESSES.contains(processName)
                && !parentProcessName.isBlank()
                && !parentProcessName.equals("explorer.exe")
                && !SYSTEM_PROCESSES.contains(parentProcessName)
                && !parentProcessName.equals(processName)) {
            return true;
        }

        return false;
    }

    private boolean isSystemProcessAnomaly(
            String processName,
            String parentProcessName
    ) {
        if (!SYSTEM_PROCESSES.contains(processName)
                || parentProcessName.isBlank()) {
            return false;
        }

        if (SYSTEM_PROCESSES.contains(parentProcessName)) {
            return false;
        }

        return !isLegitimateSystemProcessParent(
                processName,
                parentProcessName
        );
    }

    private boolean isLegitimateSystemProcessParent(
            String processName,
            String parentProcessName
    ) {
        return switch (processName) {
            case "lsass.exe" ->
                    parentProcessName.equals("wininit.exe");

            case "services.exe" ->
                    parentProcessName.equals("wininit.exe");

            case "winlogon.exe" ->
                    parentProcessName.equals("smss.exe");

            case "spoolsv.exe" ->
                    parentProcessName.equals("services.exe");

            case "svchost.exe" ->
                    parentProcessName.equals("services.exe");

            case "dllhost.exe" ->
                    parentProcessName.equals("svchost.exe");

            default -> false;
        };
    }

    private String normalize(String value) {
        if (value == null) {
            return "";
        }

        return value
                .toLowerCase(Locale.ROOT)
                .trim();
    }
}