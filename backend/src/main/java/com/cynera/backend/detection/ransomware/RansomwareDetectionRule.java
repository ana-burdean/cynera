package com.cynera.backend.detection.ransomware;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.detection.service.DetectionMatch;
import com.cynera.backend.detection.service.DetectionRule;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

@Component
public class RansomwareDetectionRule implements DetectionRule {

    private static final String RULE_NAME = "RANSOMWARE_FILE_ENCRYPTION";

    private static final Set<String> SUSPICIOUS_EXTENSIONS = Set.of(
            ".encrypted", ".locked", ".crypto", ".crypt", ".enc",
            ".ransom", ".ransomware", ".payday", ".wncry",
            ".locky", ".cerber", ".zepto", ".thor", ".aesir",
            ".zzzz", ".xyz", ".aaa", ".abc", ".micro",
            ".magic", ".r5a", ".dmn", ".onion", ".decrypt"
    );

    private static final int MASS_MODIFICATION_THRESHOLD = 20;
    private static final double MASS_MODIFICATION_RATE = 5.0;

    private final FileBehaviorTracker fileBehaviorTracker;

    public RansomwareDetectionRule(FileBehaviorTracker fileBehaviorTracker) {
        this.fileBehaviorTracker = fileBehaviorTracker;
    }

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionMatch> evaluate(SecurityEvent event) {
        if (!isFileEvent(event)) {
            return Optional.empty();
        }

        String processId = buildProcessId(event);

        fileBehaviorTracker.recordFileModification(
                processId,
                event.getFilePath(),
                mapFileAction(event.getFileAction()),
                event.getTimestamp() != null
                        ? event.getTimestamp()
                        : Instant.now()
        );

        FileBehaviorTracker.FileBehaviorSnapshot snapshot =
                fileBehaviorTracker.getSnapshot(processId);

        boolean massModification = isMassModification(snapshot);
        boolean suspiciousExtension =
                hasSuspiciousExtension(event.getFilePath());

        if (massModification && suspiciousExtension) {
            return Optional.of(new DetectionMatch(
                    Severity.CRITICAL,
                    buildDescription(snapshot, true),
                    RULE_NAME,
                    event
            ));
        }

        if (massModification) {
            return Optional.of(new DetectionMatch(
                    Severity.HIGH,
                    String.format(
                            "Mass file modification detected: %d files in %.1f sec (process: %s)",
                            snapshot.getTotalModifications(),
                            snapshot.getModificationsPerSecond(),
                            event.getProcessName()
                    ),
                    RULE_NAME,
                    event
            ));
        }

        if (suspiciousExtension) {
            return Optional.of(new DetectionMatch(
                    Severity.MEDIUM,
                    String.format(
                            "Suspicious file extension detected: %s (process: %s)",
                            event.getFilePath(),
                            event.getProcessName()
                    ),
                    RULE_NAME,
                    event
            ));
        }

        return Optional.empty();
    }

    private boolean isFileEvent(SecurityEvent event) {
        return event.getEventType() != null
                && event.getEventType().startsWith("FILE_")
                && event.getFilePath() != null
                && event.getFileAction() != null;
    }

    private String buildProcessId(SecurityEvent event) {
        return event.getHostname()
                + ":"
                + event.getProcessName()
                + ":"
                + event.getParentProcessName();
    }

    private FileBehaviorTracker.FileAction mapFileAction(String fileAction) {
        if (fileAction == null) {
            return FileBehaviorTracker.FileAction.MODIFIED;
        }

        return switch (fileAction.toUpperCase(Locale.ROOT)) {
            case "CREATED" -> FileBehaviorTracker.FileAction.CREATED;
            case "MODIFIED" -> FileBehaviorTracker.FileAction.MODIFIED;
            case "DELETED" -> FileBehaviorTracker.FileAction.DELETED;
            case "RENAMED" -> FileBehaviorTracker.FileAction.RENAMED;
            default -> FileBehaviorTracker.FileAction.MODIFIED;
        };
    }

    private boolean isMassModification(
            FileBehaviorTracker.FileBehaviorSnapshot snapshot
    ) {
        return snapshot.getTotalModifications()
                >= MASS_MODIFICATION_THRESHOLD
                && snapshot.getModificationsPerSecond()
                >= MASS_MODIFICATION_RATE;
    }

    private boolean hasSuspiciousExtension(String filePath) {
        if (filePath == null) {
            return false;
        }

        String lowerPath = filePath.toLowerCase(Locale.ROOT);

        return SUSPICIOUS_EXTENSIONS.stream()
                .anyMatch(lowerPath::endsWith);
    }

    private String buildDescription(
            FileBehaviorTracker.FileBehaviorSnapshot snapshot,
            boolean suspiciousExt
    ) {
        StringBuilder sb =
                new StringBuilder("Ransomware-like activity detected: ");

        sb.append(snapshot.getTotalModifications())
                .append(" file modifications in ");

        sb.append(String.format(
                        "%.1f",
                        snapshot.getModificationsPerSecond()
                ))
                .append(" sec");

        if (suspiciousExt) {
            sb.append(" with suspicious extensions");
        }

        sb.append(" (process: ")
                .append(snapshot.getProcessId())
                .append(")");

        return sb.toString();
    }
}