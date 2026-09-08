package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ProcessAnomalyRuleTest {

    private final ProcessAnomalyRule rule = new ProcessAnomalyRule();

    @Test
    void shouldDetectLolbins() {
        String[] lolbins = {
                "mshta.exe", "regsvr32.exe", "rundll32.exe", "regasm.exe",
                "installutil.exe", "msbuild.exe", "csc.exe", "vbc.exe",
                "jsc.exe", "wmic.exe", "cmstp.exe", "msiexec.exe"
        };

        for (String lolbin : lolbins) {
            SecurityEvent event = createEvent(lolbin, "explorer.exe", "C:\\Windows\\System32\\" + lolbin);
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect LOLBIN: " + lolbin);
        }
    }

    @Test
    void shouldDetectUnusualParentChild() {
        String[][] pairs = {
                {"cmd.exe", "winword.exe"},
                {"powershell.exe", "winword.exe"},
                {"cmd.exe", "excel.exe"},
                {"powershell.exe", "excel.exe"},
                {"cmd.exe", "outlook.exe"},
                {"powershell.exe", "outlook.exe"},
                {"cmd.exe", "acrord32.exe"},
                {"powershell.exe", "acrord32.exe"},
                {"cmd.exe", "mshta.exe"},
                {"powershell.exe", "mshta.exe"}
        };

        for (String[] pair : pairs) {
            SecurityEvent event = createEvent(pair[0], pair[1], "C:\\Windows\\System32\\" + pair[0]);
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect: " + pair[1] + " -> " + pair[0]);
        }
    }

    @Test
    void shouldDetectSystemProcessAnomaly() {
        SecurityEvent event = createEvent("lsass.exe", "cmd.exe", "C:\\Windows\\System32\\lsass.exe");
        Optional<DetectionMatch> result = rule.evaluate(event);
        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
    }

    @Test
    void shouldDetectSuspiciousSvchostParent() {
        SecurityEvent event = createEvent("svchost.exe", "cmd.exe", "C:\\Windows\\System32\\svchost.exe");
        Optional<DetectionMatch> result = rule.evaluate(event);
        assertTrue(result.isPresent());
    }

    @Test
    void shouldAllowLegitimateSystemProcessParents() {
        String[][] legitimate = {
                {"svchost.exe", "services.exe"},
                {"lsass.exe", "wininit.exe"},
                {"csrss.exe", "smss.exe"},
                {"winlogon.exe", "smss.exe"},
                {"services.exe", "wininit.exe"},
                {"spoolsv.exe", "services.exe"}
        };

        for (String[] pair : legitimate) {
            SecurityEvent event = createEvent(pair[0], pair[1], "C:\\Windows\\System32\\" + pair[0]);
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isEmpty() || result.get().severity() == Severity.LOW,
                    "Should allow legitimate: " + pair[1] + " -> " + pair[0]);
        }
    }

    @Test
    void shouldReturnCorrectRuleName() {
        assertEquals("PROCESS_ANOMALY", rule.getRuleName());
    }

    private SecurityEvent createEvent(String processName, String parentProcessName, String filePath) {
        return new SecurityEvent(
                Instant.now(),
                "PROCESS_CREATED",
                "WIN-HOST",
                "testuser",
                processName,
                parentProcessName,
                filePath, null, null, null,
                null, null, null,
                null, null, null, null,
                null, null, null, null
        );
    }
}