package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

@Component
public class SuspiciousNetworkBehaviorRule implements DetectionRule {

    private static final String RULE_NAME = "SUSPICIOUS_NETWORK_BEHAVIOR";

    private static final Set<Integer> SUSPICIOUS_PORTS = Set.of(
            4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321,
            2222, 3333, 4321, 1337, 6667, 6668, 6669, 7000, 8080, 8443
    );

    private static final Set<String> C2_PROTOCOLS = Set.of(
            "irc", "http", "https", "dns", "tcp", "udp", "raw"
    );

    private static final Set<String> SUSPICIOUS_DOMAINS = Set.of(
            ".onion", ".bit", ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
            ".top", ".club", ".work", ".info", ".cc", ".ws", ".pw"
    );

    private static final Pattern IP_PATTERN = Pattern.compile(
            "^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    );

    private static final Pattern DGA_PATTERN = Pattern.compile(
            "^[a-z0-9]{12,}\\.(com|net|org|info|biz|xyz|top|club)$"
    );

    private static final Set<String> KNOWN_C2_PATTERNS = Set.of(
            "cobaltstrike", "metasploit", "empire", "covenant", "sliver",
            "bruteratel", "havoc", "mythic", "poshc2", "koadic", "pupy"
    );

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionMatch> evaluate(SecurityEvent event) {
        if (!"NETWORK_CONNECTION".equals(event.getEventType()) &&
                !"NETWORK_LISTEN".equals(event.getEventType())) {
            return Optional.empty();
        }

        String remoteAddress = event.getRemoteAddress();
        Integer remotePort = event.getRemotePort();
        String networkProtocol = event.getNetworkProtocol() != null
                ? event.getNetworkProtocol().toLowerCase(Locale.ROOT) : "";
        String processName = event.getProcessName() != null
                ? event.getProcessName().toLowerCase(Locale.ROOT) : "";

        int threatScore = 0;
        StringBuilder reasons = new StringBuilder();

        threatScore += checkSuspiciousPort(remotePort, reasons);
        threatScore += checkSuspiciousIP(remoteAddress, reasons);
        threatScore += checkC2Patterns(processName, networkProtocol, reasons);
        threatScore += checkDgaDomains(remoteAddress, reasons);
        threatScore += checkUnusualProtocol(processName, networkProtocol, reasons);
        threatScore += checkConnectionToRarePort(processName, remotePort, reasons);

        if (threatScore >= 5) {
            return Optional.of(new DetectionMatch(
                    Severity.HIGH,
                    "Suspicious network behavior: " + reasons,
                    RULE_NAME,
                    event
            ));
        } else if (threatScore >= 3) {
            return Optional.of(new DetectionMatch(
                    Severity.MEDIUM,
                    "Anomalous network activity: " + reasons,
                    RULE_NAME,
                    event
            ));
        } else if (threatScore > 0) {
            return Optional.of(new DetectionMatch(
                    Severity.LOW,
                    "Network anomaly indicator: " + reasons,
                    RULE_NAME,
                    event
            ));
        }

        return Optional.empty();
    }

    private int checkSuspiciousPort(Integer remotePort, StringBuilder reasons) {
        if (remotePort == null) return 0;

        if (SUSPICIOUS_PORTS.contains(remotePort)) {
            return 3;
        }

        if (remotePort >= 1024 && remotePort <= 65535) {
            return 0;
        }

        return 0;
    }

    private int checkSuspiciousIP(String remoteAddress, StringBuilder reasons) {
        if (remoteAddress == null || remoteAddress.isEmpty()) return 0;

        if (IP_PATTERN.matcher(remoteAddress).matches()) {
            String[] octets = remoteAddress.split("\\.");
            int firstOctet = Integer.parseInt(octets[0]);

            if (firstOctet == 10 || firstOctet == 127 ||
                    (firstOctet == 172 && Integer.parseInt(octets[1]) >= 16 && Integer.parseInt(octets[1]) <= 31) ||
                    (firstOctet == 192 && Integer.parseInt(octets[1]) == 168)) {
                return 0;
            }

            if (firstOctet == 0 || firstOctet == 255 || firstOctet >= 224) {
                return 2;
            }
        }

        return 0;
    }

    private int checkC2Patterns(String processName, String networkProtocol, StringBuilder reasons) {
        int score = 0;

        for (String c2 : KNOWN_C2_PATTERNS) {
            if (processName.contains(c2)) {
                score += 5;
                reasons.append("Known C2 framework process: ").append(c2).append("; ");
            }
        }

        for (String proto : C2_PROTOCOLS) {
            if (networkProtocol.contains(proto)) {
                if (proto.equals("dns") || proto.equals("irc")) {
                    score += 3;
                    reasons.append("C2 protocol: ").append(proto).append("; ");
                }
            }
        }

        return score;
    }

    private int checkDgaDomains(String remoteAddress, StringBuilder reasons) {
        if (remoteAddress == null) return 0;

        if (!IP_PATTERN.matcher(remoteAddress).matches() && DGA_PATTERN.matcher(remoteAddress).matches()) {
            return 4;
        }

        for (String tld : SUSPICIOUS_DOMAINS) {
            if (remoteAddress.endsWith(tld)) {
                return 2;
            }
        }

        return 0;
    }

    private int checkUnusualProtocol(String processName, String networkProtocol, StringBuilder reasons) {
        int score = 0;

        if (processName.equals("powershell.exe") || processName.equals("pwsh.exe") ||
                processName.equals("cmd.exe") || processName.equals("wscript.exe") ||
                processName.equals("cscript.exe") || processName.equals("mshta.exe")) {
            if (networkProtocol.equals("tcp") || networkProtocol.equals("udp")) {
                score += 2;
                reasons.append("Scripting engine making raw network connections; ");
            }
        }

        return score;
    }

    private int checkConnectionToRarePort(String processName, Integer remotePort, StringBuilder reasons) {
        if (remotePort == null) return 0;

        if (remotePort < 1024 && remotePort != 80 && remotePort != 443 &&
                remotePort != 53 && remotePort != 22 && remotePort != 21 &&
                remotePort != 25 && remotePort != 110 && remotePort != 143 &&
                remotePort != 389 && remotePort != 636 && remotePort != 135 &&
                remotePort != 445 && remotePort != 139 && remotePort != 3389 &&
                remotePort != 5985 && remotePort != 5986) {
            return 2;
        }

        return 0;
    }
}