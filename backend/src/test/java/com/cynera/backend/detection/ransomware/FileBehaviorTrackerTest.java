package com.cynera.backend.detection.ransomware;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class FileBehaviorTrackerTest {

    private FileBehaviorTracker tracker;

    @BeforeEach
    void setUp() {
        tracker = new FileBehaviorTracker(10, 100);
    }

    @Test
    void shouldTrackFileCreations() {
        String processId = "proc-123";
        Instant now = Instant.now();

        tracker.recordFileModification(processId, "C:\\test\\file1.txt", FileBehaviorTracker.FileAction.CREATED);
        tracker.recordFileModification(processId, "C:\\test\\file2.txt", FileBehaviorTracker.FileAction.CREATED);

        FileBehaviorTracker.FileBehaviorSnapshot snapshot = tracker.getSnapshot(processId);

        assertEquals(2, snapshot.getTotalModifications());
        assertEquals(2, snapshot.getCreations());
        assertEquals(0, snapshot.getModifications());
    }

    @Test
    void shouldTrackMixedFileActions() {
        String processId = "proc-456";

        tracker.recordFileModification(processId, "C:\\test\\a.txt", FileBehaviorTracker.FileAction.CREATED);
        tracker.recordFileModification(processId, "C:\\test\\b.txt", FileBehaviorTracker.FileAction.MODIFIED);
        tracker.recordFileModification(processId, "C:\\test\\c.txt", FileBehaviorTracker.FileAction.DELETED);
        tracker.recordFileModification(processId, "C:\\test\\d.txt", FileBehaviorTracker.FileAction.RENAMED);

        FileBehaviorTracker.FileBehaviorSnapshot snapshot = tracker.getSnapshot(processId);

        assertEquals(4, snapshot.getTotalModifications());
        assertEquals(1, snapshot.getCreations());
        assertEquals(1, snapshot.getModifications());
        assertEquals(1, snapshot.getDeletions());
        assertEquals(1, snapshot.getRenames());
    }

    @Test
    void shouldPruneOldEventsOutsideWindow() {
        String processId = "proc-789";
        Instant now = Instant.now();
        Instant old = now.minusSeconds(20);

        tracker.recordFileModification(processId, "C:\\test\\old.txt", FileBehaviorTracker.FileAction.CREATED, old);
        tracker.recordFileModification(processId, "C:\\test\\new.txt", FileBehaviorTracker.FileAction.CREATED, now);

        FileBehaviorTracker.FileBehaviorSnapshot snapshot = tracker.getSnapshot(processId);

        assertEquals(1, snapshot.getTotalModifications());
    }

    @Test
    void shouldCalculateModificationsPerSecond() {
        String processId = "proc-rate";
        Instant start = Instant.now().minusSeconds(10);

        tracker.recordFileModification(processId, "C:\\test\\f1.txt", FileBehaviorTracker.FileAction.CREATED, start);
        tracker.recordFileModification(processId, "C:\\test\\f2.txt", FileBehaviorTracker.FileAction.CREATED, start.plusSeconds(1));
        tracker.recordFileModification(processId, "C:\\test\\f3.txt", FileBehaviorTracker.FileAction.CREATED, start.plusSeconds(3));

        FileBehaviorTracker.FileBehaviorSnapshot snapshot = tracker.getSnapshot(processId);

        double rate = snapshot.getModificationsPerSecond();
        assertTrue(rate > 0.5);
        assertTrue(rate < 2.0);
    }

    @Test
    void shouldReturnEmptySnapshotForUnknownProcess() {
        FileBehaviorTracker.FileBehaviorSnapshot snapshot = tracker.getSnapshot("unknown-process");

        assertEquals(0, snapshot.getTotalModifications());
        assertEquals("unknown-process", snapshot.getProcessId());
    }

    @Test
    void shouldRemoveProcess() {
        String processId = "proc-remove";

        tracker.recordFileModification(processId, "C:\\test\\file.txt", FileBehaviorTracker.FileAction.CREATED);
        tracker.removeProcess(processId);

        FileBehaviorTracker.FileBehaviorSnapshot snapshot = tracker.getSnapshot(processId);
        assertEquals(0, snapshot.getTotalModifications());
    }

    @Test
    void shouldCleanupStaleProcesses() {
        String staleProcess = "stale-proc";
        String activeProcess = "active-proc";
        Instant oldTime = Instant.now().minusSeconds(30);
        Instant now = Instant.now();

        tracker.recordFileModification(staleProcess, "C:\\test\\old.txt", FileBehaviorTracker.FileAction.CREATED, oldTime);
        tracker.recordFileModification(activeProcess, "C:\\test\\new.txt", FileBehaviorTracker.FileAction.CREATED, now);

        tracker.cleanup(Instant.now().minusSeconds(15));

        assertEquals(0, tracker.getSnapshot(staleProcess).getTotalModifications());
        assertEquals(1, tracker.getSnapshot(activeProcess).getTotalModifications());
    }

    @Test
    void shouldRespectMaxEventsLimit() {
        FileBehaviorTracker limitedTracker = new FileBehaviorTracker(60, 5);
        String processId = "proc-limited";

        for (int i = 0; i < 10; i++) {
            limitedTracker.recordFileModification(processId, "C:\\test\\file" + i + ".txt",
                    FileBehaviorTracker.FileAction.MODIFIED);
        }

        FileBehaviorTracker.FileBehaviorSnapshot snapshot = limitedTracker.getSnapshot(processId);
        assertEquals(5, snapshot.getTotalModifications());
    }

    @Test
    void shouldTrackSeparateProcessesIndependently() {
        tracker.recordFileModification("proc-A", "C:\\a.txt", FileBehaviorTracker.FileAction.CREATED);
        tracker.recordFileModification("proc-A", "C:\\b.txt", FileBehaviorTracker.FileAction.CREATED);
        tracker.recordFileModification("proc-B", "C:\\c.txt", FileBehaviorTracker.FileAction.CREATED);

        assertEquals(2, tracker.getSnapshot("proc-A").getTotalModifications());
        assertEquals(1, tracker.getSnapshot("proc-B").getTotalModifications());
    }

    @Test
    void shouldHandleRapidModifications() {
        String processId = "proc-rapid";
        Instant base = Instant.now().minusSeconds(10);

        for (int i = 0; i < 50; i++) {
            tracker.recordFileModification(processId, "C:\\test\\file" + i + ".txt",
                    FileBehaviorTracker.FileAction.MODIFIED, base.plusMillis(i * 10));
        }

        FileBehaviorTracker.FileBehaviorSnapshot snapshot = tracker.getSnapshot(processId);
        assertEquals(50, snapshot.getTotalModifications());
        assertEquals(50, snapshot.getModifications());
        assertTrue(snapshot.getModificationsPerSecond() > 100);
    }
}