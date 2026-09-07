package com.cynera.backend.event.dto;

import com.cynera.backend.event.entity.SecurityEvent;

import java.time.Instant;

public record EventResponse(
        Long id,
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
        String registryValueData,
        String windowsEventChannel,
        Integer windowsEventId,
        String windowsEventProvider,
        String windowsEventMessage
) {

    public EventResponse(Long id, Instant timestamp, String eventType, String hostname,
            String username, String processName, String parentProcessName,
            String filePath, String fileAction, Long fileSize, String fileHash,
            String remoteAddress, Integer remotePort, String networkProtocol,
            String registryPath, String registryAction, String registryValueName,
            String registryValueData) {
        this(id, timestamp, eventType, hostname, username, processName,
                parentProcessName, filePath, fileAction, fileSize, fileHash,
                remoteAddress, remotePort, networkProtocol, registryPath,
                registryAction, registryValueName, registryValueData,
                null, null, null, null);
    }

    public EventResponse(
            Long id, Instant timestamp, String eventType, String hostname,
            String username, String processName, String parentProcessName,
            String filePath, String fileAction, Long fileSize, String fileHash,
            String remoteAddress, Integer remotePort, String networkProtocol
    ) {
        this(id, timestamp, eventType, hostname, username, processName,
                parentProcessName, filePath, fileAction, fileSize, fileHash,
                remoteAddress, remotePort, networkProtocol,
                null, null, null, null);
    }

    public EventResponse(
            Long id, Instant timestamp, String eventType, String hostname,
            String username, String processName, String parentProcessName,
            String filePath, String fileAction, Long fileSize, String fileHash
    ) {
        this(
                id, timestamp, eventType, hostname, username, processName,
                parentProcessName, filePath, fileAction, fileSize, fileHash,
                null, null, null
        );
    }

    public EventResponse(
            Long id,
            Instant timestamp,
            String eventType,
            String hostname,
            String username,
            String processName,
            String parentProcessName
    ) {
        this(
                id,
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

    public static EventResponse from(SecurityEvent event) {
        return new EventResponse(
                event.getId(),
                event.getTimestamp(),
                event.getEventType(),
                event.getHostname(),
                event.getUsername(),
                event.getProcessName(),
                event.getParentProcessName(),
                event.getFilePath(),
                event.getFileAction(),
                event.getFileSize(),
                event.getFileHash(),
                event.getRemoteAddress(),
                event.getRemotePort(),
                event.getNetworkProtocol(),
                event.getRegistryPath(),
                event.getRegistryAction(),
                event.getRegistryValueName(),
                event.getRegistryValueData(),
                event.getWindowsEventChannel(),
                event.getWindowsEventId(),
                event.getWindowsEventProvider(),
                event.getWindowsEventMessage()
        );
    }
}
