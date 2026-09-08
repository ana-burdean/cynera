package com.cynera.backend.detection.response.service;
import com.cynera.backend.detection.response.entity.ResponseAction;
import com.cynera.backend.detection.response.repository.ResponseActionRepository;

import com.cynera.backend.agent.entity.Agent;
import com.cynera.backend.agent.repository.AgentRepository;
import com.cynera.backend.agent.service.AgentCommandService;
import com.cynera.backend.detection.entity.Detection;
import com.cynera.backend.detection.entity.SecurityIncident;
import com.cynera.backend.detection.repository.SecurityIncidentRepository;
import com.cynera.backend.detection.ransomware.ProtectedFileService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class ResponseService {

    private static final Logger log = LoggerFactory.getLogger(ResponseService.class);

    private final ResponseActionRepository actionRepository;
    private final AgentCommandService agentCommandService;
    private final AgentRepository agentRepository;
    private final ProtectedFileService protectedFileService;
    private final SecurityIncidentRepository incidentRepository;

    public ResponseService(ResponseActionRepository actionRepository,
                           AgentCommandService agentCommandService,
                           AgentRepository agentRepository,
                           ProtectedFileService protectedFileService,
                           SecurityIncidentRepository incidentRepository) {
        this.actionRepository = actionRepository;
        this.agentCommandService = agentCommandService;
        this.agentRepository = agentRepository;
        this.protectedFileService = protectedFileService;
        this.incidentRepository = incidentRepository;
    }

    @Transactional
    public ResponseAction executeKillProcess(Long incidentId, Long detectionId, String processId, String processName, String triggeredBy) {
        return executeAction(incidentId, detectionId, "KILL_PROCESS", processName,
                Map.of("processId", processId, "processName", processName), triggeredBy);
    }

    @Transactional
    public ResponseAction executeQuarantineFile(Long incidentId, Long detectionId, String filePath, String reason, String triggeredBy) {
        return executeAction(incidentId, detectionId, "QUARANTINE_FILE", filePath,
                Map.of("filePath", filePath, "reason", reason), triggeredBy);
    }

    @Transactional
    public ResponseAction executeIsolateEndpoint(Long incidentId, Long detectionId, String hostname, String reason, String triggeredBy) {
        return executeAction(incidentId, detectionId, "ISOLATE_ENDPOINT", hostname,
                Map.of("hostname", hostname, "reason", reason), triggeredBy);
    }

    @Transactional
    public ResponseAction executeProtectFile(Long incidentId, Long detectionId, String filePath, String triggeredBy) {
        if (!protectedFileService.isProtected(filePath)) {
            protectedFileService.protectFile(filePath, "Protected via response action");
        }
        return executeAction(incidentId, detectionId, "PROTECT_FILE", filePath,
                Map.of("filePath", filePath), triggeredBy);
    }

    @Transactional
    public ResponseAction executeUnprotectFile(Long incidentId, Long detectionId, String filePath, String triggeredBy) {
        protectedFileService.unprotectFile(filePath);
        return executeAction(incidentId, detectionId, "UNPROTECT_FILE", filePath,
                Map.of("filePath", filePath), triggeredBy);
    }

    @Transactional
    public ResponseAction executeBlockNetworkConnection(Long incidentId, Long detectionId, String remoteAddress, Integer remotePort, String triggeredBy) {
        return executeAction(incidentId, detectionId, "BLOCK_NETWORK", remoteAddress + ":" + remotePort,
                Map.of("remoteAddress", remoteAddress, "remotePort", remotePort), triggeredBy);
    }

    private ResponseAction executeAction(Long incidentId, Long detectionId, String actionType,
                                          String targetIdentifier, Map<String, Object> parameters, String triggeredBy) {
        String actionId = UUID.randomUUID().toString();
        String correlationId = "resp-" + actionId.substring(0, 8);

        Optional<Agent> agentOpt = findAgentForAction(incidentId, actionType);
        String agentToken = agentOpt.map(Agent::getAgentToken).orElse(null);

        ResponseAction action = new ResponseAction(
                actionId, actionType, targetIdentifier, parameters,
                incidentId, detectionId, triggeredBy, agentToken, correlationId
        );

        if (agentToken != null) {
            action.setStatus(ResponseAction.Status.EXECUTING);
            action.setStartedAt(Instant.now());
            dispatchToAgent(action, agentToken);
        } else {
            log.warn("No agent found for action {}, marking as failed", actionId);
            action.setStatus(ResponseAction.Status.FAILED);
            action.setResultMessage("No agent available for target");
            action.setCompletedAt(Instant.now());
        }

        return actionRepository.save(action);
    }

    private Optional<Agent> findAgentForAction(Long incidentId, String actionType) {
        if (incidentId != null) {
            Optional<SecurityIncident> incidentOpt = incidentRepository.findById(incidentId);
            if (incidentOpt.isPresent()) {
                String hostname = incidentOpt.get().getHostname();
                return agentRepository.findByHostname(hostname);
            }
        }
        return Optional.empty();
    }

    private void dispatchToAgent(ResponseAction action, String agentToken) {
        try {
            action.setStatus(ResponseAction.Status.EXECUTING);
            action.setStartedAt(Instant.now());

            switch (action.getActionType()) {
                case "KILL_PROCESS" -> agentCommandService.sendKillProcessCommand(
                        agentToken,
                        (String) action.getParameters().get("processId"),
                        (String) action.getParameters().get("processName"),
                        action.getCorrelationId()
                );
                case "QUARANTINE_FILE" -> agentCommandService.sendQuarantineFileCommand(
                        agentToken,
                        (String) action.getParameters().get("filePath"),
                        (String) action.getParameters().get("reason"),
                        action.getCorrelationId()
                );
                case "ISOLATE_ENDPOINT" -> agentCommandService.sendIsolateEndpointCommand(
                        agentToken,
                        (String) action.getParameters().get("hostname"),
                        (String) action.getParameters().get("reason"),
                        action.getCorrelationId()
                );
                case "PROTECT_FILE" -> agentCommandService.sendProtectFileCommand(
                        agentToken,
                        (String) action.getParameters().get("filePath"),
                        action.getCorrelationId()
                );
                case "UNPROTECT_FILE" -> agentCommandService.sendUnprotectFileCommand(
                        agentToken,
                        (String) action.getParameters().get("filePath"),
                        action.getCorrelationId()
                );
                case "BLOCK_NETWORK" -> {
                    // Would integrate with network blocking mechanism
                    log.info("Network block requested: {}", action.getParameters());
                }
            }

            log.info("Dispatched action {} to agent", action.getActionId());
        } catch (Exception e) {
            log.error("Failed to dispatch action {}", action.getActionId(), e);
            action.setStatus(ResponseAction.Status.FAILED);
            action.setResultMessage("Dispatch failed: " + e.getMessage());
            action.setCompletedAt(Instant.now());
            actionRepository.save(action);
        }
    }

    @Transactional
    public void handleCommandResult(String agentToken, String actionId, boolean success, String message, Map<String, Object> details) {
        Optional<ResponseAction> actionOpt = actionRepository.findByActionId(actionId);
        if (actionOpt.isEmpty()) {
            log.warn("Action {} not found for result", actionId);
            return;
        }

        ResponseAction action = actionOpt.get();
        action.setStatus(success ? ResponseAction.Status.COMPLETED : ResponseAction.Status.FAILED);
        action.setResultMessage(message);
        action.setResultDetails(details);
        action.setCompletedAt(Instant.now());
        actionRepository.save(action);

        log.info("Action {} completed with status: {}", actionId, action.getStatus());
    }

    @Transactional(readOnly = true)
    public List<ResponseAction> getActionsForIncident(Long incidentId) {
        return actionRepository.findByIncidentId(incidentId);
    }

    @Transactional(readOnly = true)
    public List<ResponseAction> getActionsForDetection(Long detectionId) {
        return actionRepository.findByDetectionId(detectionId);
    }

    @Transactional(readOnly = true)
    public List<ResponseAction> getPendingActions() {
        return actionRepository.findByStatus(ResponseAction.Status.PENDING);
    }

    @Transactional(readOnly = true)
    public List<ResponseAction> getActionsByAgent(String agentToken) {
        return actionRepository.findByAgentToken(agentToken);
    }

    @Transactional
    public void cancelAction(Long actionId, String reason) {
        Optional<ResponseAction> actionOpt = actionRepository.findById(actionId);
        if (actionOpt.isPresent()) {
            ResponseAction action = actionOpt.get();
            if (action.getStatus() == ResponseAction.Status.PENDING || action.getStatus() == ResponseAction.Status.EXECUTING) {
                action.setStatus(ResponseAction.Status.CANCELLED);
                action.setResultMessage("Cancelled: " + reason);
                action.setCompletedAt(Instant.now());
                actionRepository.save(action);
            }
        }
    }

    @Transactional
    public void cleanupStaleActions() {
        List<ResponseAction.Status> staleStatuses = List.of(
                ResponseAction.Status.PENDING, ResponseAction.Status.EXECUTING
        );
        Instant cutoff = Instant.now().minusSeconds(300); // 5 minutes
        List<ResponseAction> stale = actionRepository.findStaleActions(staleStatuses, cutoff);

        for (ResponseAction action : stale) {
            action.setStatus(ResponseAction.Status.TIMEOUT);
            action.setResultMessage("Action timed out");
            action.setCompletedAt(Instant.now());
            actionRepository.save(action);
            log.warn("Action {} timed out", action.getActionId());
        }
    }

    @Transactional
    public ResponseAction autoRespondToCriticalIncident(SecurityIncident incident, List<Detection> detections) {
        log.info("Auto-responding to critical incident {}", incident.getId());

        for (Detection detection : detections) {
            if (detection.getSeverity() == com.cynera.backend.detection.model.Severity.CRITICAL) {
                String hostname = incident.getHostname();
                String processName = detection.getRule();

                if ("RANSOMWARE_FILE_ENCRYPTION".equals(detection.getRule())) {
                    executeKillProcess(incident.getId(), detection.getId(), "unknown", processName, "AUTO");
                    executeIsolateEndpoint(incident.getId(), detection.getId(), hostname, "Critical ransomware incident", "AUTO");
                    return actionRepository.findByIncidentId(incident.getId()).get(0);
                }
            }
        }
        return null;
    }
}