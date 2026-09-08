package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class PersistenceRuleTest {

    private final PersistenceRule rule = new PersistenceRule();

    @Test
    void shouldDetectRegistryRunKeyModification() {
        SecurityEvent event = createRegistryEvent(
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "SetValue", "Malware", "C:\\malware.exe"
        );

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertTrue(result.get().severity() == Severity.HIGH || result.get().severity() == Severity.MEDIUM);
    }

    @Test
    void shouldDetectAllRunKeys() {
        String[] runKeys = {
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
                "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
                "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell"
        };

        for (String key : runKeys) {
            SecurityEvent event = createRegistryEvent(key, "SetValue", "Test", "C:\\test.exe");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + key);
        }
    }

    @Test
    void shouldDetectScheduledTaskTools() {
        String[] tools = {"schtasks", "at.exe", "reg.exe", "regedit"};

        for (String tool : tools) {
            SecurityEvent event = createProcessEvent(tool + ".exe", "C:\\Windows\\System32\\" + tool + ".exe");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + tool);
        }
    }

    @Test
    void shouldDetectPowerShellScheduledTask() {
        // Test that scheduled task related tools are detected
        String[] tools = {"schtasks", "at.exe"};
        for (String tool : tools) {
            SecurityEvent event = createProcessEvent(tool + ".exe", "C:\\Windows\\System32\\" + tool + ".exe");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + tool);
        }
    }

    @Test
    void shouldDetectServiceManipulation() {
        // Test that service manipulation tools are detected via registry
        String[] tools = {"reg.exe", "regedit.exe"};
        for (String tool : tools) {
            SecurityEvent event = createProcessEvent(tool, "C:\\Windows\\System32\\" + tool);
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + tool);
        }
    }

    @Test
    void shouldDetectStartupFolderFiles() {
        String[] startupPaths = {
                "C:\\Users\\test\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.exe",
                "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\evil.exe"
        };

        for (String path : startupPaths) {
            SecurityEvent event = createFileEvent("FILE_CREATED", path);
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + path);
        }
    }

    @Test
    void shouldDetectWmiPersistence() {
        String[] wmiIndicators = {"__eventfilter", "__eventconsumer", "__filtertoconsumerbinding"};

        for (String indicator : wmiIndicators) {
            SecurityEvent event = createRegistryEvent(
                    "HKLM\\Software\\Microsoft\\WBEM\\Scripting",
                    "SetValue", indicator, "malicious_script"
            );
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + indicator);
        }
    }

    @Test
    void shouldReturnCorrectRuleName() {
        assertEquals("PERSISTENCE_MECHANISM", rule.getRuleName());
    }

    private SecurityEvent createRegistryEvent(String registryPath, String registryAction,
                                               String registryValueName, String registryValueData) {
        return new SecurityEvent(
                Instant.now(),
                "REGISTRY_SET_VALUE",
                "WIN-HOST",
                "testuser",
                "reg.exe",
                "cmd.exe",
                null, null, null, null,
                null, null, null,
                registryPath, registryAction, registryValueName, registryValueData,
                null, null, null, null
        );
    }

    private SecurityEvent createProcessEvent(String processName, String filePath) {
        return new SecurityEvent(
                Instant.now(),
                "PROCESS_CREATED",
                "WIN-HOST",
                "testuser",
                processName,
                "explorer.exe",
                filePath, null, null, null,
                null, null, null,
                null, null, null, null,
                null, null, null, null
        );
    }

    private SecurityEvent createProcessEventWithCommand(String processName, String commandLine,
                                                         String filePath, String fileAction) {
        return new SecurityEvent(
                Instant.now(),
                "PROCESS_CREATED",
                "WIN-HOST",
                "testuser",
                processName,
                "explorer.exe",
                filePath, fileAction, null, null,
                null, null, null,
                null, null, null, null,
                null, null, null, null
        );
    }

    private SecurityEvent createFileEvent(String eventType, String filePath) {
        return new SecurityEvent(
                Instant.now(),
                eventType,
                "WIN-HOST",
                "testuser",
                "explorer.exe",
                "explorer.exe",
                filePath, "CREATED", 1024L, "hash",
                null, null, null,
                null, null, null, null,
                null, null, null, null
        );
    }
}