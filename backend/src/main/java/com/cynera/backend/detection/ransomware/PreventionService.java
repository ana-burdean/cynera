package com.cynera.backend.detection.ransomware;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.repository.AgentRepository;
import com.cynera.backend.agent.service.AgentCommandService;
import com.cynera.backend.detection.entity.SecurityIncident;
import com.cynera.backend.detection.service.DetectionMatch;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class PreventionService {

    private final AgentCommandService agentCommandService;
    private final AgentRepository agentRepository;
    private final ProtectedFileService protectedFileService;

    public PreventionService(AgentCommandService agentCommandService,
                             AgentRepository agentRepository,
                             ProtectedFileService protectedFileService) {
        this.agentCommandService = agentCommandService;
        this.agentRepository = agentRepository;
        this.protectedFileService = protectedFileService;
    }

    public void handleCriticalRansomwareIncident(SecurityIncident incident, List<DetectionMatch> detections) {
        Optional<DetectionMatch> ransomwareMatch = detections.stream()
                .filter(d -> "RANSOMWARE_FILE_ENCRYPTION".equals(d.rule()))
                .findFirst();

        if (ransomwareMatch.isEmpty() || ransomwareMatch.get().event() == null) {
            return;
        }

        SecurityEvent event = ransomwareMatch.get().event();
        String correlationId = "ransomware-" + incident.getId();
        String agentToken = getAgentTokenForHost(event.getHostname());

        agentCommandService.sendKillProcessCommand(
                agentToken,
                extractProcessId(event),
                event.getProcessName(),
                correlationId
        );

        if (event.getFilePath() != null) {
            agentCommandService.sendQuarantineFileCommand(
                    agentToken,
                    event.getFilePath(),
                    "Ransomware encryption detected - " + ransomwareMatch.get().description(),
                    correlationId
            );
        }

        agentCommandService.sendIsolateEndpointCommand(
                agentToken,
                event.getHostname(),
                "Critical ransomware incident: " + ransomwareMatch.get().description(),
                correlationId
        );
    }

    public void handleHighSeverityFileActivity(String agentToken, SecurityEvent event, String reason) {
        String correlationId = "high-severity-" + System.currentTimeMillis();

        agentCommandService.sendKillProcessCommand(
                agentToken, 
                extractProcessId(event), 
                event.getProcessName(), 
                correlationId
        );
        
        if (event.getFilePath() != null) {
            agentCommandService.sendQuarantineFileCommand(agentToken, event.getFilePath(), reason, correlationId);
        }
    }

    public void protectAllCriticalFiles() {
        List<String> filePaths = protectedFileService.getAllProtectedFiles()
                .stream()
                .map(ProtectedFile::getFilePath)
                .toList();

        if (filePaths.isEmpty()) {
            return;
        }

        agentRepository.findAll().stream()
                .filter(Agent::isEnabled)
                .forEach(agent -> protectCriticalFiles(agent.getAgentToken(), filePaths));
    }
    public void protectCriticalFiles(String agentToken, List<String> filePaths) {
        String correlationId = "protect-" + System.currentTimeMillis();
        filePaths.forEach(path -> {
            if (!protectedFileService.isProtected(path)) {
                protectedFileService.protectFile(path, "Auto-protected by prevention service");
            }
            agentCommandService.sendProtectFileCommand(agentToken, path, correlationId);
        });
    }

    public void unprotectFiles(String agentToken, List<String> filePaths) {
        String correlationId = "unprotect-" + System.currentTimeMillis();
        filePaths.forEach(path -> {
            agentCommandService.sendUnprotectFileCommand(agentToken, path, correlationId);
        });
    }

    public boolean isFileProtected(String filePath) {
        return protectedFileService.isProtected(filePath);
    }

    public void initializeSystemProtection() {
        protectedFileService.initializeDefaultProtectedFiles();
    }

    private String getAgentTokenForHost(String hostname) {
        return agentRepository.findByHostname(hostname)
                .map(Agent::getAgentToken)
                .orElseThrow(() -> new IllegalArgumentException("No agent found for hostname: " + hostname));
    }

    private String extractProcessId(SecurityEvent event) {
        return event.getProcessName() + "-" + event.getParentProcessName();
    }
}