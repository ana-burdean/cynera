package com.cynera.backend.detection.ransomware;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.detection.service.DetectionMatch;
import com.cynera.backend.event.entity.SecurityEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class RansomwareDetectionRuleTest {

    private FileBehaviorTracker fileBehaviorTracker;
    private RansomwareDetectionRule rule;

    @BeforeEach
    void setUp() {
        fileBehaviorTracker = new FileBehaviorTracker(10, 1000);
        rule = new RansomwareDetectionRule(fileBehaviorTracker);
    }

    @Test
    void shouldReturnEmptyForNonFileEvents() {
        SecurityEvent event = createEvent("PROCESS_CREATED", "notepad.exe", null, null, null);

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldReturnEmptyForFileEventWithoutPathOrAction() {
        SecurityEvent event = createEvent("FILE_CREATED", "test.exe", null, "CREATED", null);
        Optional<DetectionMatch> result = rule.evaluate(event);
        assertTrue(result.isEmpty());

        event = createEvent("FILE_CREATED", "test.exe", "C:\\test.txt", null, null);
        result = rule.evaluate(event);
        assertTrue(result.isEmpty());
    }

    @Test
    void shouldDetectSuspiciousExtension() {
        SecurityEvent event = createEvent("FILE_CREATED", "ransomware.exe", "C:\\test.encrypted", "CREATED", "hash1");

        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isPresent());
        assertEquals(Severity.MEDIUM, result.get().severity());
        assertTrue(result.get().description().contains(".encrypted"));
    }

    @Test
    void shouldDetectMultipleSuspiciousExtensions() {
        String[] extensions = {".locked", ".crypto", ".crypt", ".enc", ".ransom", ".wncry", ".locky"};

        for (String ext : extensions) {
            fileBehaviorTracker.removeProcess("WIN-HOST:ransomware.exe:explorer.exe");
            SecurityEvent event = createEvent("FILE_CREATED", "ransomware.exe", "C:\\file" + ext, "CREATED", "hash");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect extension: " + ext);
            assertEquals(Severity.MEDIUM, result.get().severity());
        }
    }

    @Test
    void shouldNotDetectNormalExtensions() {
        String[] normalFiles = {"C:\\test.txt", "C:\\test.doc", "C:\\test.pdf", "C:\\test.jpg", "C:\\test.exe"};

        for (String file : normalFiles) {
            fileBehaviorTracker.removeProcess("WIN-HOST:test.exe:explorer.exe");
            SecurityEvent event = createEvent("FILE_CREATED", "test.exe", file, "CREATED", "hash");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isEmpty(), "Should not detect: " + file);
        }
    }

    @Test
    void shouldDetectMassModification() {
        String processId = "WIN-HOST:encryptor.exe:explorer.exe";
        Instant base = Instant.now().minusSeconds(10);

        for (int i = 0; i < 25; i++) {
            SecurityEvent event = createEvent("FILE_MODIFIED", "encryptor.exe", "C:\\file" + i + ".txt", "MODIFIED", "hash" + i);
            rule.evaluate(event);
        }

        SecurityEvent finalEvent = createEvent("FILE_MODIFIED", "encryptor.exe", "C:\\file25.txt", "MODIFIED", "hash25");
        Optional<DetectionMatch> result = rule.evaluate(finalEvent);

        assertTrue(result.isPresent());
        assertEquals(Severity.HIGH, result.get().severity());
        assertTrue(result.get().description().contains("Mass file modification"));
    }

    @Test
    void shouldDetectRansomwareCriticalMassModificationWithSuspiciousExtension() {
        String processId = "WIN-HOST:encryptor.exe:explorer.exe";
        Instant base = Instant.now().minusSeconds(10);

        for (int i = 0; i < 25; i++) {
            SecurityEvent event = createEvent("FILE_MODIFIED", "encryptor.exe", "C:\\file" + i + ".txt", "MODIFIED", "hash" + i);
            rule.evaluate(event);
        }

        SecurityEvent suspiciousEvent = createEvent("FILE_MODIFIED", "encryptor.exe", "C:\\important.encrypted", "MODIFIED", "hash25");
        Optional<DetectionMatch> result = rule.evaluate(suspiciousEvent);

        assertTrue(result.isPresent());
        assertEquals(Severity.CRITICAL, result.get().severity());
        assertTrue(result.get().description().contains("Ransomware-like activity"));
        assertTrue(result.get().description().contains("suspicious extensions"));
    }

    @Test
    void shouldDetectMassCreationWithSuspiciousExtension() {
        String processId = "WIN-HOST:encryptor.exe:explorer.exe";
        Instant base = Instant.now().minusSeconds(10);

        for (int i = 0; i < 25; i++) {
            SecurityEvent event = createEvent("FILE_CREATED", "encryptor.exe", "C:\\newfile" + i + ".txt", "CREATED", "hash" + i);
            rule.evaluate(event);
        }

        SecurityEvent suspiciousEvent = createEvent("FILE_CREATED", "encryptor.exe", "C:\\data.locked", "CREATED", "hash25");
        Optional<DetectionMatch> result = rule.evaluate(suspiciousEvent);

        assertTrue(result.isPresent());
        assertEquals(Severity.CRITICAL, result.get().severity());
    }

    @Test
    void shouldTrackProcessesIndependently() {
        Instant base = Instant.now().minusSeconds(10);

        for (int i = 0; i < 15; i++) {
            SecurityEvent event1 = createEvent("FILE_MODIFIED", "proc1.exe", "C:\\a" + i + ".txt", "MODIFIED", "hash" + i);
            rule.evaluate(event1);
        }

        for (int i = 0; i < 15; i++) {
            SecurityEvent event2 = createEvent("FILE_MODIFIED", "proc2.exe", "C:\\b" + i + ".txt", "MODIFIED", "hash" + i);
            rule.evaluate(event2);
        }

        SecurityEvent event1 = createEvent("FILE_MODIFIED", "proc1.exe", "C:\\a15.txt", "MODIFIED", "hash15");
        Optional<DetectionMatch> result1 = rule.evaluate(event1);

        SecurityEvent event2 = createEvent("FILE_MODIFIED", "proc2.exe", "C:\\b15.txt", "MODIFIED", "hash15");
        Optional<DetectionMatch> result2 = rule.evaluate(event2);

        assertTrue(result1.isEmpty());
        assertTrue(result2.isEmpty());
    }

    @Test
    void shouldNotTriggerBelowMassThreshold() {
        Instant base = Instant.now().minusSeconds(10);

        for (int i = 0; i < 15; i++) {
            SecurityEvent event = createEvent("FILE_MODIFIED", "test.exe", "C:\\file" + i + ".txt", "MODIFIED", "hash" + i);
            rule.evaluate(event);
        }

        SecurityEvent event = createEvent("FILE_MODIFIED", "test.exe", "C:\\file15.txt", "MODIFIED", "hash15");
        Optional<DetectionMatch> result = rule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldNotTriggerBelowRateThreshold() {
        FileBehaviorTracker slowTracker = new FileBehaviorTracker(200, 1000);
        RansomwareDetectionRule slowRule = new RansomwareDetectionRule(slowTracker);
        Instant base = Instant.now().minusSeconds(200);

        for (int i = 0; i < 10; i++) {
            SecurityEvent event = createEvent("FILE_MODIFIED", "slow.exe", "C:\\file" + i + ".txt", "MODIFIED", "hash" + i, base.plusSeconds(i * 20));
            slowRule.evaluate(event);
        }

        SecurityEvent event = createEvent("FILE_MODIFIED", "slow.exe", "C:\\file10.txt", "MODIFIED", "hash10", base.plusSeconds(200));
        Optional<DetectionMatch> result = slowRule.evaluate(event);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldHandleCaseInsensitiveExtensions() {
        String[] extensions = {".ENCRYPTED", ".Locked", ".CrYpTo", ".EnC"};

        for (String ext : extensions) {
            fileBehaviorTracker.removeProcess("WIN-HOST:test.exe:explorer.exe");
            SecurityEvent event = createEvent("FILE_CREATED", "test.exe", "C:\\FILE" + ext, "CREATED", "hash");
            Optional<DetectionMatch> result = rule.evaluate(event);
            assertTrue(result.isPresent(), "Should detect case insensitive: " + ext);
        }
    }

    @Test
    void shouldReturnCorrectRuleName() {
        assertEquals("RANSOMWARE_FILE_ENCRYPTION", rule.getRuleName());
    }

    private SecurityEvent createEvent(String eventType, String processName, String filePath, String fileAction, String fileHash) {
        return createEvent(eventType, processName, filePath, fileAction, fileHash, Instant.now());
    }

    private SecurityEvent createEvent(String eventType, String processName, String filePath, String fileAction, String fileHash, Instant timestamp) {
        return new SecurityEvent(
                timestamp,
                eventType,
                "WIN-HOST",
                "testuser",
                processName,
                "explorer.exe",
                filePath,
                fileAction,
                1024L,
                fileHash,
                null, null, null,
                null, null, null, null,
                null, null, null, null
        );
    }
}