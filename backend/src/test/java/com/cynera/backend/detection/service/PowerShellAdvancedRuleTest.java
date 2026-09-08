package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class PowerShellAdvancedRuleTest {

    private final PowerShellAdvancedRule rule = new PowerShellAdvancedRule();

    @Test
    void shouldReturnEmptyForNonPowerShellProcess() {
        SecurityEvent event = createEvent("cmd.exe", null, null, null);

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldDetectObfuscationPatterns() {
        String[] patterns = {"-enc", "-encodedcommand", "-ep bypass", "-windowstyle hidden", "-nop", "-noprofile"};

        for (String pattern : patterns) {
            SecurityEvent event = createEvent("powershell.exe", pattern, "test.ps1", null);
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + pattern);
            assertTrue(result.get().severity() == Severity.MEDIUM || result.get().severity() == Severity.HIGH || result.get().severity() == Severity.CRITICAL);
        }
    }

    @Test
    void shouldDetectDownloadCradles() {
        String[] cradles = {
                "invoke-webrequest", "iwr http://evil.com", "net.webclient",
                "downloadstring", "downloadfile", "invoke-expression", "iex",
                "new-object net.webclient", "system.net.http.httpclient"
        };

        for (String cradle : cradles) {
            SecurityEvent event = createEvent("powershell.exe", cradle, "test.ps1", null);
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + cradle);
        }
    }

    @Test
    void shouldDetectAmsiBypass() {
        String[] bypasses = {
                "amsiutils", "amsiinitfailed", "reflection", "assembly.load",
                "getfield", "nonpublic", "static", "setvalue", "virtualprotect"
        };

        for (String bypass : bypasses) {
            SecurityEvent event = createEvent("powershell.exe", bypass, "test.ps1", null);
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + bypass);
        }
    }

    @Test
    void shouldDetectKnownOffensiveTools() {
        String[] tools = {
                "invoke-mimikatz", "invoke-bloodhound", "invoke-kerberoast",
                "get-gpppassword", "find-gpplocation", "get-vaultcredential",
                "get-keystrokes", "get-timedscreenshot", "invoke-portscan",
                "invoke-reversepowershell", "invoke-shellcode", "inject-shellcode",
                "get-system", "bypassuac", "invoke-psinject"
        };

        for (String tool : tools) {
            SecurityEvent event = createEvent("powershell.exe", tool, "test.ps1", null);
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + tool);
            assertEquals(Severity.CRITICAL, result.get().severity());
        }
    }

    @Test
    void shouldDetectBase64EncodedContent() {
        SecurityEvent event = createEvent("powershell.exe",
                "JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA=",
                "test.ps1", null);
        Optional<DetectionMatch> result = rule.evaluate(event);
        assertTrue(result.isPresent());
    }

    @Test
    void shouldBeCaseInsensitive() {
        SecurityEvent event = createEvent("PowerShell.EXE", "-EnCoDeDCoMmAnD", "test.ps1", null);
        Optional<DetectionMatch> result = rule.evaluate(event);
        assertTrue(result.isPresent());
    }

    @Test
    void shouldReturnCorrectRuleName() {
        assertEquals("POWERSHELL_ADVANCED_THREAT", rule.getRuleName());
    }

    private SecurityEvent createEvent(String processName, String commandLine, String filePath, String fileAction) {
        return new SecurityEvent(
                Instant.now(),
                "PROCESS_CREATED",
                "WIN-HOST",
                "testuser",
                processName,
                "explorer.exe",
                commandLine,
                fileAction,
                1024L,
                "hash",
                null, null, null,
                null, null, null, null,
                null, null, null, null
        );
    }
}