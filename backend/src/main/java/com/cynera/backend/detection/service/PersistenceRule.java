package com.cynera.backend.detection.service;

import com.cynera.backend.detection.model.Severity;
import com.cynera.backend.event.entity.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

@Component
public class PersistenceRule implements DetectionRule {

    private static final String RULE_NAME = "PERSISTENCE_MECHANISM";

    private static final Set<String> REGISTRY_RUN_KEYS = Set.of(
            "hkcu\\software\\microsoft\\windows\\currentversion\\run",
            "hkcu\\software\\microsoft\\windows\\currentversion\\runonce",
            "hkcu\\software\\microsoft\\windows\\currentversion\\runonceex",
            "hklm\\software\\microsoft\\windows\\currentversion\\run",
            "hklm\\software\\microsoft\\windows\\currentversion\\runonce",
            "hklm\\software\\microsoft\\windows\\currentversion\\runonceex",
            "hklm\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
            "hkcu\\software\\microsoft\\windows\\currentversion\\policies\\explorer\\run",
            "hklm\\software\\microsoft\\windows nt\\currentversion\\winlogon\\userinit",
            "hklm\\software\\microsoft\\windows nt\\currentversion\\winlogon\\shell",
            "hklm\\software\\microsoft\\windows nt\\currentversion\\image file execution options",
            "hkcu\\software\\microsoft\\windows\\currentversion\\explorer\\user shell folders",
            "hklm\\software\\microsoft\\windows\\currentversion\\explorer\\user shell folders"
    );

    private static final Set<String> SCHEDULED_TASK_PATHS = Set.of(
            "\\microsoft\\windows\\powershell\\scheduledjobs",
            "\\microsoft\\windows\\powershell\\",
            "\\microsoft\\windows\\task scheduler\\",
            "\\windows defender\\",
            "\\updateorchestrator\\"
    );

    private static final Set<String> SERVICE_KEYWORDS = Set.of(
            "createservice", "startservice", "configservice", "sc create", "sc config",
            "new-service", "set-service", "start-process.*service"
    );

    private static final Set<String> STARTUP_FOLDERS = Set.of(
            "\\startup\\",
            "\\start menu\\programs\\startup\\",
            "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
            "\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\"
    );

    private static final Set<String> WMI_PERSISTENCE = Set.of(
            "__eventfilter", "__eventconsumer", "__filtertoConsumerBinding",
            "commandlinetemplate", "activatescript", "script", "filter", "consumer"
    );

    private static final Set<String> PERSISTENCE_TOOLS = Set.of(
            "schtasks", "at.exe", "reg.exe", "regedit", "regini", "regadd",
            "powershell.*register-scheduledtask", "powershell.*new-scheduledtask",
            "powershell.*new-service", "powershell.*set-service",
            "wmic.*create", "wmic.*process.*call.*create"
    );

    @Override
    public String getRuleName() {
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionMatch> evaluate(SecurityEvent event) {
        String eventType = event.getEventType();
        if (eventType == null) {
            return Optional.empty();
        }

        String processName = event.getProcessName() != null ? event.getProcessName().toLowerCase(Locale.ROOT) : "";
        String filePath = event.getFilePath() != null ? event.getFilePath().toLowerCase(Locale.ROOT) : "";
        String registryPath = event.getRegistryPath() != null ? event.getRegistryPath().toLowerCase(Locale.ROOT) : "";
        String registryAction = event.getRegistryAction() != null ? event.getRegistryAction().toLowerCase(Locale.ROOT) : "";
        String registryValueName = event.getRegistryValueName() != null ? event.getRegistryValueName().toLowerCase(Locale.ROOT) : "";
        String registryValueData = event.getRegistryValueData() != null ? event.getRegistryValueData().toLowerCase(Locale.ROOT) : "";

        int threatScore = 0;
        StringBuilder reasons = new StringBuilder();

        if (eventType.startsWith("REGISTRY_")) {
            threatScore += checkRegistryPersistence(registryPath, registryAction, registryValueName, registryValueData, reasons);
            threatScore += checkWmiPersistence(registryPath, registryValueName, registryValueData, reasons);
        }

        if (eventType.startsWith("FILE_") || eventType.startsWith("PROCESS_")) {
            threatScore += checkFilePersistence(processName, filePath, reasons);
            threatScore += checkScheduledTaskPersistence(processName, filePath, reasons);
            threatScore += checkServicePersistence(processName, filePath, reasons);
            threatScore += checkStartupFolderPersistence(filePath, reasons);
            threatScore += checkWmiPersistence(registryPath, registryValueName, registryValueData, reasons);
        }

        if (threatScore >= 5) {
            return Optional.of(new DetectionMatch(
                    Severity.HIGH,
                    "Persistence mechanism detected: " + reasons,
                    RULE_NAME,
                    event
            ));
        } else if (threatScore >= 3) {
            return Optional.of(new DetectionMatch(
                    Severity.MEDIUM,
                    "Potential persistence activity: " + reasons,
                    RULE_NAME,
                    event
            ));
        } else if (threatScore > 0) {
            return Optional.of(new DetectionMatch(
                    Severity.LOW,
                    "Suspicious persistence indicator: " + reasons,
                    RULE_NAME,
                    event
            ));
        }

        return Optional.empty();
    }

    private int checkRegistryPersistence(String registryPath, String registryAction,
                                          String registryValueName, String registryValueData,
                                          StringBuilder reasons) {
        int score = 0;

        if (!"setvalue".equals(registryAction) && !"createkey".equals(registryAction)) {
            return 0;
        }

        for (String runKey : REGISTRY_RUN_KEYS) {
            if (registryPath.contains(runKey)) {
                score += 4;
                reasons.append("Registry Run key modification: ").append(registryPath).append("; ");
            }
        }

        if (registryValueData != null && !registryValueData.isEmpty()) {
            for (String tool : PERSISTENCE_TOOLS) {
                if (registryValueData.contains(tool)) {
                    score += 3;
                    reasons.append("Persistence tool in registry value: ").append(tool).append("; ");
                }
            }
        }

        return score;
    }

    private int checkFilePersistence(String processName, String filePath, StringBuilder reasons) {
        int score = 0;

        for (String folder : STARTUP_FOLDERS) {
            if (filePath.contains(folder)) {
                score += 4;
                reasons.append("File in Startup folder: ").append(filePath).append("; ");
            }
        }

        if (processName.contains("schtasks") || processName.contains("at.exe")) {
            score += 3;
            reasons.append("Scheduled task utility executed: ").append(processName).append("; ");
        }

        return score;
    }

    private int checkScheduledTaskPersistence(String processName, String filePath, StringBuilder reasons) {
        int score = 0;

        String combined = (processName + " " + filePath).toLowerCase(Locale.ROOT);

        for (String taskPath : SCHEDULED_TASK_PATHS) {
            if (combined.contains(taskPath)) {
                score += 3;
                reasons.append("Scheduled task path accessed: ").append(taskPath).append("; ");
            }
        }

        for (String tool : PERSISTENCE_TOOLS) {
            if (combined.contains(tool.replace("powershell.*", "").replace("wmic.*", ""))) {
                score += 2;
                reasons.append("Task scheduler tool: ").append(tool).append("; ");
            }
        }

        return score;
    }

    private int checkServicePersistence(String processName, String filePath, StringBuilder reasons) {
        int score = 0;

        String combined = (processName + " " + filePath).toLowerCase(Locale.ROOT);

        for (String keyword : SERVICE_KEYWORDS) {
            if (combined.contains(keyword)) {
                score += 3;
                reasons.append("Service manipulation detected: ").append(keyword).append("; ");
            }
        }

        return score;
    }

    private int checkStartupFolderPersistence(String filePath, StringBuilder reasons) {
        int score = 0;

        for (String folder : STARTUP_FOLDERS) {
            if (filePath.contains(folder)) {
                score += 4;
                reasons.append("Startup folder file: ").append(filePath).append("; ");
            }
        }

        return score;
    }

    private int checkWmiPersistence(String registryPath, String registryValueName,
                                     String registryValueData, StringBuilder reasons) {
        int score = 0;

        String combined = (registryPath + " " + registryValueName + " " + registryValueData).toLowerCase(Locale.ROOT);

        for (String wmi : WMI_PERSISTENCE) {
            if (combined.contains(wmi)) {
                score += 4;
                reasons.append("WMI persistence indicator: ").append(wmi).append("; ");
            }
        }

        return score;
    }
}