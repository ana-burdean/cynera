package com.cynera.backend.event.entity;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "security_events")
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Instant timestamp;

    @Column(nullable = false)
    private String eventType;

    @Column(nullable = false)
    private String hostname;

    private String username;

    private String processName;

    private String parentProcessName;

    private String filePath;

    private String fileAction;

    private Long fileSize;

    private String fileHash;

    private String remoteAddress;

    private Integer remotePort;

    private String networkProtocol;

    private String registryPath;

    private String registryAction;

    private String registryValueName;

    private String registryValueData;

    private String windowsEventChannel;

    private Integer windowsEventId;

    private String windowsEventProvider;

    private String windowsEventMessage;

    protected SecurityEvent() {
    }

    // Constructor used by existing process/detection tests
    public SecurityEvent(
            Instant timestamp,
            String eventType,
            String hostname,
            String username,
            String processName,
            String parentProcessName
    ) {
        this(
                timestamp,
                eventType,
                hostname,
                username,
                processName,
                parentProcessName,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }

    // Constructor with file telemetry
    public SecurityEvent(
            Instant timestamp,
            String eventType,
            String hostname,
            String username,
            String processName,
            String parentProcessName,
            String filePath,
            String fileAction,
            Long fileSize,
            String fileHash
    ) {
        this(
                timestamp, eventType, hostname, username, processName,
                parentProcessName, filePath, fileAction, fileSize, fileHash,
                null, null, null
        );
    }

    public SecurityEvent(
            Instant timestamp,
            String eventType,
            String hostname,
            String username,
            String processName,
            String parentProcessName,
            String filePath,
            String fileAction,
            Long fileSize,
            String fileHash,
            String remoteAddress,
            Integer remotePort,
            String networkProtocol
    ) {
        this(timestamp, eventType, hostname, username, processName,
                parentProcessName, filePath, fileAction, fileSize, fileHash,
                remoteAddress, remotePort, networkProtocol,
                null, null, null, null);
    }

    public SecurityEvent(
            Instant timestamp,
            String eventType,
            String hostname,
            String username,
            String processName,
            String parentProcessName,
            String filePath,
            String fileAction,
            Long fileSize,
            String fileHash,
            String remoteAddress,
            Integer remotePort,
            String networkProtocol,
            String registryPath,
            String registryAction,
            String registryValueName,
            String registryValueData
    ) {
        this(timestamp, eventType, hostname, username, processName,
                parentProcessName, filePath, fileAction, fileSize, fileHash,
                remoteAddress, remotePort, networkProtocol, registryPath,
                registryAction, registryValueName, registryValueData,
                null, null, null, null);
    }

    public SecurityEvent(
            Instant timestamp, String eventType, String hostname, String username,
            String processName, String parentProcessName, String filePath,
            String fileAction, Long fileSize, String fileHash, String remoteAddress,
            Integer remotePort, String networkProtocol, String registryPath,
            String registryAction, String registryValueName, String registryValueData,
            String windowsEventChannel, Integer windowsEventId,
            String windowsEventProvider, String windowsEventMessage
    ) {
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.hostname = hostname;
        this.username = username;
        this.processName = processName;
        this.parentProcessName = parentProcessName;
        this.filePath = filePath;
        this.fileAction = fileAction;
        this.fileSize = fileSize;
        this.fileHash = fileHash;
        this.remoteAddress = remoteAddress;
        this.remotePort = remotePort;
        this.networkProtocol = networkProtocol;
        this.registryPath = registryPath;
        this.registryAction = registryAction;
        this.registryValueName = registryValueName;
        this.registryValueData = registryValueData;
        this.windowsEventChannel = windowsEventChannel;
        this.windowsEventId = windowsEventId;
        this.windowsEventProvider = windowsEventProvider;
        this.windowsEventMessage = windowsEventMessage;
    }

    public Long getId() {
        return id;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getEventType() {
        return eventType;
    }

    public String getHostname() {
        return hostname;
    }

    public String getUsername() {
        return username;
    }

    public String getProcessName() {
        return processName;
    }

    public String getParentProcessName() {
        return parentProcessName;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getFileAction() {
        return fileAction;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public String getFileHash() {
        return fileHash;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }

    public Integer getRemotePort() {
        return remotePort;
    }

    public String getNetworkProtocol() {
        return networkProtocol;
    }

    public String getRegistryPath() { return registryPath; }

    public String getRegistryAction() { return registryAction; }

    public String getRegistryValueName() { return registryValueName; }

    public String getRegistryValueData() { return registryValueData; }

    public String getWindowsEventChannel() { return windowsEventChannel; }
    public Integer getWindowsEventId() { return windowsEventId; }
    public String getWindowsEventProvider() { return windowsEventProvider; }
    public String getWindowsEventMessage() { return windowsEventMessage; }
}
