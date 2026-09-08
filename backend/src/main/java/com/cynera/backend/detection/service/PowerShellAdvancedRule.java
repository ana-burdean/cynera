package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

@Component
public class PowerShellAdvancedRule implements DetectionRule {

    private static final String RULE_NAME = "POWERSHELL_ADVANCED_THREAT";

    private static final Set<String> OBFUSCATION_PATTERNS = Set.of(
            "-enc", "-encodedcommand", "-e ", "-ep bypass", "-executionpolicy bypass",
            "-windowstyle hidden", "-w hidden", "-nop", "-noprofile", "-sta", "-noninteractive"
    );

    private static final Set<String> DOWNLOAD_CRADLES = Set.of(
            "invoke-webrequest", "iwr", "net.webclient", "downloadstring", "downloadfile",
            "invoke-expression", "iex", "[system.net.webclient]", "new-object net.webclient",
            "system.net.http", "httpclient", "webclient.downloaddata"
    );

    private static final Set<String> AMSI_BYPASS_PATTERNS = Set.of(
            "amsiutils", "amsiinitfailed", "reflection", "assembly.load",
            "getfield", "nonpublic", "static", "setvalue", "memorystream",
            "virtualprotect", "ntdll", "kernel32", "writeprocessmemory"
    );

    private static final Set<String> SUSPICIOUS_COMMANDS = Set.of(
            "invoke-mimikatz", "invoke-bloodhound", "invoke-kerberoast", "get-gpppassword",
            "find-gpplocation", "get-vaultcredential", "get-keystrokes", "get-timedscreenshot",
            "invoke-portscan", "invoke-reversepowershell", "invoke-shellcode", "inject-shellcode",
            "get-system", "enable-duplicateToken", "bypassuac", "invoke-psinject",
            "invoke-reflectivepeinjection", "invoke-dllinjection", "invoke-wmicommand"
    );

    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]+={0,2}$");

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

        if (!processName.equals("powershell.exe") && !processName.equals("pwsh.exe")) {
            return Optional.empty();
        }

        String commandLine = buildCommandLine(event);
        if (commandLine == null || commandLine.isEmpty()) {
            return Optional.empty();
        }

        String lowerCommand = commandLine.toLowerCase(Locale.ROOT);

        boolean hasObfuscation = OBFUSCATION_PATTERNS.stream().anyMatch(lowerCommand::contains);
        boolean hasDownloadCradle = DOWNLOAD_CRADLES.stream().anyMatch(lowerCommand::contains);
        boolean hasAmsiBypass = AMSI_BYPASS_PATTERNS.stream().anyMatch(lowerCommand::contains);
        boolean hasSuspiciousCommand = SUSPICIOUS_COMMANDS.stream().anyMatch(lowerCommand::contains);
        boolean hasBase64 = detectBase64(commandLine);

        int threatScore = 0;
        StringBuilder reasons = new StringBuilder();

        if (hasObfuscation) {
            threatScore += 3;
            reasons.append("Obfuscation detected; ");
        }
        if (hasDownloadCradle) {
            threatScore += 4;
            reasons.append("Download cradle detected; ");
        }
        if (hasAmsiBypass) {
            threatScore += 5;
            reasons.append("AMSI bypass attempt; ");
        }
        if (hasSuspiciousCommand) {
            threatScore += 5;
            reasons.append("Known offensive tooling; ");
        }
        if (hasBase64) {
            threatScore += 2;
            reasons.append("Base64 encoded content; ");
        }

        if (threatScore >= 5) {
            return Optional.of(new DetectionMatch(
                    Severity.CRITICAL,
                    "Advanced PowerShell threat: " + reasons,
                    RULE_NAME,
                    event
            ));
        } else if (threatScore >= 3) {
            return Optional.of(new DetectionMatch(
                    Severity.HIGH,
                    "Suspicious PowerShell activity: " + reasons,
                    RULE_NAME,
                    event
            ));
        } else if (threatScore > 0) {
            return Optional.of(new DetectionMatch(
                    Severity.MEDIUM,
                    "PowerShell anomaly: " + reasons,
                    RULE_NAME,
                    event
            ));
        }

        return Optional.empty();
    }

    private String buildCommandLine(SecurityEvent event) {
        StringBuilder cmd = new StringBuilder();
        if (event.getProcessName() != null) cmd.append(event.getProcessName()).append(" ");
        if (event.getFilePath() != null) cmd.append(event.getFilePath()).append(" ");
        if (event.getFileAction() != null && !"null".equalsIgnoreCase(event.getFileAction())) cmd.append(event.getFileAction());
        return cmd.toString().trim();
    }

    private boolean detectBase64(String input) {
        String[] parts = input.split("\\s+");
        for (String part : parts) {
            if (part.length() > 20 && BASE64_PATTERN.matcher(part).matches()) {
                return true;
            }
        }
        return false;
    }
}