package com.cynera.backend.event.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

public record EventRequest(

        @NotNull(message = "timestamp is required")
        Instant timestamp,

        @NotBlank(message = "eventType is required")
        String eventType,

        @NotBlank(message = "hostname is required")
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

        public EventRequest(Instant timestamp, String eventType, String hostname,
                String username, String processName, String parentProcessName,
                String filePath, String fileAction, Long fileSize, String fileHash,
                String remoteAddress, Integer remotePort, String networkProtocol,
                String registryPath, String registryAction, String registryValueName,
                String registryValueData) {
                this(timestamp, eventType, hostname, username, processName,
                        parentProcessName, filePath, fileAction, fileSize, fileHash,
                        remoteAddress, remotePort, networkProtocol, registryPath,
                        registryAction, registryValueName, registryValueData,
                        null, null, null, null);
        }

        public EventRequest(
                Instant timestamp, String eventType, String hostname, String username,
                String processName, String parentProcessName, String filePath,
                String fileAction, Long fileSize, String fileHash,
                String remoteAddress, Integer remotePort, String networkProtocol
        ) {
                this(timestamp, eventType, hostname, username, processName,
                        parentProcessName, filePath, fileAction, fileSize, fileHash,
                        remoteAddress, remotePort, networkProtocol,
                        null, null, null, null);
        }

        public EventRequest(
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
                        parentProcessName, filePath, fileAction, fileSize,
                        fileHash, null, null, null
                );
        }

        public EventRequest(
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
}
