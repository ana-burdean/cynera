package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SuspiciousNetworkBehaviorRuleTest {

    private final SuspiciousNetworkBehaviorRule rule = new SuspiciousNetworkBehaviorRule();

    @Test
    void shouldReturnEmptyForNonNetworkEvents() {
        SecurityEvent event = createEvent("PROCESS_CREATED", "powershell.exe", null, null, null);

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldDetectSuspiciousPorts() {
        int[] suspiciousPorts = {4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321};

        for (int port : suspiciousPorts) {
            SecurityEvent event = createNetworkEvent("powershell.exe", "192.168.1.100", port, "tcp");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect port: " + port);
        }
    }

    @Test
    void shouldDetectSuspiciousIPs() {
        String[] suspiciousIPs = {"8.8.8.8", "1.1.1.1", "208.67.222.222"};

        for (String ip : suspiciousIPs) {
            SecurityEvent event = createNetworkEvent("powershell.exe", ip, 443, "tcp");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect IP: " + ip);
        }
    }

    @Test
    void shouldAllowPrivateIPs() {
        String[] privateIPs = {"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"};

        for (String ip : privateIPs) {
            SecurityEvent event = createNetworkEvent("powershell.exe", ip, 443, "tcp");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isEmpty() || result.get().severity() == Severity.LOW,
                    "Should allow private IP: " + ip);
        }
    }

    @Test
    void shouldDetectKnownC2Frameworks() {
        String[] c2Frameworks = {"cobaltstrike", "metasploit", "empire", "covenant", "sliver"};

        for (String c2 : c2Frameworks) {
            SecurityEvent event = createNetworkEvent(c2 + ".exe", "192.168.1.100", 443, "tcp");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect C2: " + c2);
            assertEquals(Severity.HIGH, result.get().severity());
        }
    }

    @Test
    void shouldDetectDgaDomains() {
        String[] dgaDomains = {
                "abcdefghijklmnop.com",
                "randomdomain123456789.net",
                "malwarec2server12345.org"
        };

        for (String domain : dgaDomains) {
            SecurityEvent event = createNetworkEvent("powershell.exe", domain, 80, "tcp");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect DGA: " + domain);
        }
    }

    @Test
    void shouldDetectSuspiciousTLDs() {
        String[] suspiciousTLDs = {
                "evil.onion", "malware.bit", "c2.tk", "bad.ml",
                "malicious.ga", "trojan.cf", "virus.gq"
        };

        for (String domain : suspiciousTLDs) {
            SecurityEvent event = createNetworkEvent("powershell.exe", domain, 80, "tcp");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect TLD: " + domain);
        }
    }

    @Test
    void shouldDetectScriptingEnginesMakingConnections() {
        String[] scriptingEngines = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"};

        for (String engine : scriptingEngines) {
            SecurityEvent event = createNetworkEvent(engine, "192.168.1.100", 80, "tcp");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + engine);
        }
    }

    @Test
    void shouldReturnCorrectRuleName() {
        assertEquals("SUSPICIOUS_NETWORK_BEHAVIOR", rule.getRuleName());
    }

    private SecurityEvent createEvent(String eventType, String processName,
                                       String remoteAddress, Integer remotePort, String networkProtocol) {
        return new SecurityEvent(
                Instant.now(),
                eventType,
                "WIN-HOST",
                "testuser",
                processName,
                "explorer.exe",
                null, null, null, null,
                remoteAddress, remotePort, networkProtocol,
                null, null, null, null,
                null, null, null, null
        );
    }

    private SecurityEvent createNetworkEvent(String processName, String remoteAddress,
                                              Integer remotePort, String networkProtocol) {
        return createEvent("NETWORK_CONNECTION", processName, remoteAddress, remotePort, networkProtocol);
    }
}