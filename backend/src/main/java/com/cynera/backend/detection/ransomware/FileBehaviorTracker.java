package com.cynera.backend.detection.ransomware;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class FileBehaviorTracker {

    private static final int DEFAULT_WINDOW_SECONDS = 10;
    private static final int DEFAULT_MAX_EVENTS = 1000;

    private final Map<String, ProcessFileActivity> processActivity = new ConcurrentHashMap<>();
    private final int windowSeconds;
    private final int maxEventsPerProcess;

    public FileBehaviorTracker() {
        this(DEFAULT_WINDOW_SECONDS, DEFAULT_MAX_EVENTS);
    }

    public FileBehaviorTracker(int windowSeconds, int maxEventsPerProcess) {
        this.windowSeconds = windowSeconds;
        this.maxEventsPerProcess = maxEventsPerProcess;
    }

    public void recordFileModification(String processId, String filePath, FileAction action) {
        recordFileModification(processId, filePath, action, Instant.now());
    }

    public void recordFileModification(String processId, String filePath, FileAction action, Instant timestamp) {
        ProcessFileActivity activity = processActivity.computeIfAbsent(
                processId,
                k -> new ProcessFileActivity(processId, windowSeconds, maxEventsPerProcess)
        );
        activity.recordModification(filePath, action, timestamp);
    }

    public Optional<ProcessFileActivity> getActivity(String processId) {
        return Optional.ofNullable(processActivity.get(processId));
    }

    public FileBehaviorSnapshot getSnapshot(String processId) {
        ProcessFileActivity activity = processActivity.get(processId);
        if (activity == null) {
            Instant now = Instant.now();
            return new FileBehaviorSnapshot(processId, 0, 0, 0, 0, 0, now, now);
        }
        return activity.getSnapshot();
    }

    public void cleanup(Instant olderThan) {
        processActivity.entrySet().removeIf(entry -> entry.getValue().isStale(olderThan));
    }

    public void removeProcess(String processId) {
        processActivity.remove(processId);
    }

    public static class FileBehaviorSnapshot {
        private final String processId;
        private final int totalModifications;
        private final int creations;
        private final int modifications;
        private final int deletions;
        private final int renames;
        private final Instant windowStart;
        private final Instant windowEnd;

        public FileBehaviorSnapshot(String processId, int totalModifications, int creations,
                                    int modifications, int deletions, int renames,
                                    Instant windowStart, Instant windowEnd) {
            this.processId = processId;
            this.totalModifications = totalModifications;
            this.creations = creations;
            this.modifications = modifications;
            this.deletions = deletions;
            this.renames = renames;
            this.windowStart = windowStart;
            this.windowEnd = windowEnd;
        }

        public String getProcessId() { return processId; }
        public int getTotalModifications() { return totalModifications; }
        public int getCreations() { return creations; }
        public int getModifications() { return modifications; }
        public int getDeletions() { return deletions; }
        public int getRenames() { return renames; }
        public Instant getWindowStart() { return windowStart; }
        public Instant getWindowEnd() { return windowEnd; }

        public double getModificationsPerSecond() {
            long windowDurationMillis = java.time.Duration.between(windowStart, windowEnd).toMillis();
            if (windowDurationMillis <= 0) return totalModifications;
            return (double) totalModifications / (windowDurationMillis / 1000.0);
        }
    }

    private static class ProcessFileActivity {
        private final String processId;
        private final int windowSeconds;
        private final int maxEvents;
        private final Deque<FileEvent> events = new ArrayDeque<>();
        private int creations = 0;
        private int modifications = 0;
        private int deletions = 0;
        private int renames = 0;

        ProcessFileActivity(String processId, int windowSeconds, int maxEvents) {
            this.processId = processId;
            this.windowSeconds = windowSeconds;
            this.maxEvents = maxEvents;
        }

        void recordModification(String filePath, FileAction action, Instant timestamp) {
            pruneOldEvents(timestamp);

            while (events.size() >= maxEvents) {
                FileEvent removed = events.pollFirst();
                decrementCounter(removed.action());
            }

            events.addLast(new FileEvent(filePath, action, timestamp));
            incrementCounter(action);
        }

        private void pruneOldEvents(Instant now) {
            Instant cutoff = now.minusSeconds(windowSeconds);
            while (!events.isEmpty() && events.peekFirst().timestamp().isBefore(cutoff)) {
                FileEvent removed = events.pollFirst();
                decrementCounter(removed.action());
            }
        }

        private void incrementCounter(FileAction action) {
            switch (action) {
                case CREATED -> creations++;
                case MODIFIED -> modifications++;
                case DELETED -> deletions++;
                case RENAMED -> renames++;
            }
        }

        private void decrementCounter(FileAction action) {
            switch (action) {
                case CREATED -> creations--;
                case MODIFIED -> modifications--;
                case DELETED -> deletions--;
                case RENAMED -> renames--;
            }
        }

        FileBehaviorSnapshot getSnapshot() {
            Instant windowStart = events.isEmpty() ? Instant.now() : events.peekFirst().timestamp();
            Instant windowEnd = events.isEmpty() ? Instant.now() : events.peekLast().timestamp();
            int total = creations + modifications + deletions + renames;
            return new FileBehaviorSnapshot(processId, total, creations, modifications, deletions, renames, windowStart, windowEnd);
        }

        boolean isStale(Instant olderThan) {
            return events.isEmpty() || events.peekLast().timestamp().isBefore(olderThan);
        }

        private record FileEvent(String filePath, FileAction action, Instant timestamp) {}
    }

    public enum FileAction {
        CREATED, MODIFIED, DELETED, RENAMED
    }
}