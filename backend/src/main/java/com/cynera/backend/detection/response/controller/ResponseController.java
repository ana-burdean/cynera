package com.cynera.backend.detection.response.controller;
import com.cynera.backend.detection.response.entity.ResponseAction;
import com.cynera.backend.detection.response.service.ResponseService;

import com.cynera.backend.agent.dto.AgentCommandResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/response")
public class ResponseController {

    private final ResponseService responseService;

    public ResponseController(ResponseService responseService) {
        this.responseService = responseService;
    }

    @PostMapping("/kill-process")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseAction killProcess(@RequestBody KillProcessRequest request) {
        return responseService.executeKillProcess(
                request.incidentId(), request.detectionId(),
                request.processId(), request.processName(), request.triggeredBy()
        );
    }

    @PostMapping("/quarantine-file")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseAction quarantineFile(@RequestBody QuarantineFileRequest request) {
        return responseService.executeQuarantineFile(
                request.incidentId(), request.detectionId(),
                request.filePath(), request.reason(), request.triggeredBy()
        );
    }

    @PostMapping("/isolate-endpoint")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseAction isolateEndpoint(@RequestBody IsolateEndpointRequest request) {
        return responseService.executeIsolateEndpoint(
                request.incidentId(), request.detectionId(),
                request.hostname(), request.reason(), request.triggeredBy()
        );
    }

    @PostMapping("/protect-file")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseAction protectFile(@RequestBody ProtectFileRequest request) {
        return responseService.executeProtectFile(
                request.incidentId(), request.detectionId(),
                request.filePath(), request.triggeredBy()
        );
    }

    @PostMapping("/unprotect-file")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseAction unprotectFile(@RequestBody UnprotectFileRequest request) {
        return responseService.executeUnprotectFile(
                request.incidentId(), request.detectionId(),
                request.filePath(), request.triggeredBy()
        );
    }

    @PostMapping("/block-network")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public ResponseAction blockNetwork(@RequestBody BlockNetworkRequest request) {
        return responseService.executeBlockNetworkConnection(
                request.incidentId(), request.detectionId(),
                request.remoteAddress(), request.remotePort(), request.triggeredBy()
        );
    }

    @GetMapping("/incident/{incidentId}")
    public List<ResponseAction> getActionsForIncident(@PathVariable Long incidentId) {
        return responseService.getActionsForIncident(incidentId);
    }

    @GetMapping("/detection/{detectionId}")
    public List<ResponseAction> getActionsForDetection(@PathVariable Long detectionId) {
        return responseService.getActionsForDetection(detectionId);
    }

    @GetMapping("/pending")
    public List<ResponseAction> getPendingActions() {
        return responseService.getPendingActions();
    }

    @GetMapping("/agent/{agentToken}")
    public List<ResponseAction> getActionsByAgent(@PathVariable String agentToken) {
        return responseService.getActionsByAgent(agentToken);
    }

    @PostMapping("/{actionId}/result")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void reportActionResult(
            @PathVariable String actionId,
            @Valid @RequestBody AgentCommandResponse response
    ) {
        responseService.handleCommandResult(
                null, actionId, response.success(),
                response.message(), response.details()
        );
    }

    @PostMapping("/{actionId}/cancel")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void cancelAction(@PathVariable Long actionId, @RequestBody Map<String, String> body) {
        String reason = body.getOrDefault("reason", "Cancelled by user");
        responseService.cancelAction(actionId, reason);
    }

    @PostMapping("/cleanup")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void cleanupStaleActions() {
        responseService.cleanupStaleActions();
    }

    public record KillProcessRequest(Long incidentId, Long detectionId, String processId, String processName, String triggeredBy) {}
    public record QuarantineFileRequest(Long incidentId, Long detectionId, String filePath, String reason, String triggeredBy) {}
    public record IsolateEndpointRequest(Long incidentId, Long detectionId, String hostname, String reason, String triggeredBy) {}
    public record ProtectFileRequest(Long incidentId, Long detectionId, String filePath, String triggeredBy) {}
    public record UnprotectFileRequest(Long incidentId, Long detectionId, String filePath, String triggeredBy) {}
    public record BlockNetworkRequest(Long incidentId, Long detectionId, String remoteAddress, Integer remotePort, String triggeredBy) {}
}