package com.cynera.backend.agent.dto;

import jakarta.validation.constraints.NotBlank;

import java.time.Instant;

public record AgentEventRequest(
        @NotBlank String eventType,
        @NotBlank String hostname,
        String username,
        String processName,
        String parentProcessName,
        Instant timestamp,
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

        public AgentEventRequest(String eventType, String hostname, String username,
                String processName, String parentProcessName, Instant timestamp,
                String filePath, String fileAction, Long fileSize, String fileHash,
                String remoteAddress, Integer remotePort, String networkProtocol,
                String registryPath, String registryAction, String registryValueName,
                String registryValueData) {
                this(eventType, hostname, username, processName, parentProcessName,
                        timestamp, filePath, fileAction, fileSize, fileHash,
                        remoteAddress, remotePort, networkProtocol, registryPath,
                        registryAction, registryValueName, registryValueData,
                        null, null, null, null);
        }

        public AgentEventRequest(
                String eventType, String hostname, String username,
                String processName, String parentProcessName, Instant timestamp,
                String filePath, String fileAction, Long fileSize, String fileHash,
                String remoteAddress, Integer remotePort, String networkProtocol
        ) {
                this(eventType, hostname, username, processName, parentProcessName,
                        timestamp, filePath, fileAction, fileSize, fileHash,
                        remoteAddress, remotePort, networkProtocol,
                        null, null, null, null);
        }

        public AgentEventRequest(
                String eventType,
                String hostname,
                String username,
                String processName,
                String parentProcessName,
                Instant timestamp,
                String filePath,
                String fileAction,
                Long fileSize,
                String fileHash
        ) {
                this(
                        eventType, hostname, username, processName,
                        parentProcessName, timestamp, filePath, fileAction,
                        fileSize, fileHash, null, null, null
                );
        }

        public AgentEventRequest(
                String eventType,
                String hostname,
                String username,
                String processName,
                String parentProcessName,
                Instant timestamp
        ) {
                this(
                        eventType,
                        hostname,
                        username,
                        processName,
                        parentProcessName,
                        timestamp,
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
