package com.cynera.backend.detection.ransomware;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Service
public class ProtectedFileService {

    private final ProtectedFileRepository repository;

    public ProtectedFileService(ProtectedFileRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public ProtectedFile protectFile(String filePath, String description) {
        Optional<ProtectedFile> existing = repository.findByFilePath(filePath);

        if (existing.isPresent()) {
            ProtectedFile protectedFile = existing.get();

            if (protectedFile.isActive()) {
                throw new IllegalArgumentException("File already protected: " + filePath);
            }

            protectedFile.setActive(true);
            protectedFile.setDescription(description);
            protectedFile.setUpdatedAt(Instant.now());
            return repository.save(protectedFile);
        }

        ProtectedFile protectedFile = new ProtectedFile(filePath, description);
        return repository.save(protectedFile);
    }

    @Transactional
    public void unprotectFile(String filePath) {
        Optional<ProtectedFile> existing = repository.findByFilePath(filePath);
        if (existing.isPresent()) {
            ProtectedFile pf = existing.get();
            pf.setActive(false);
            pf.setUpdatedAt(Instant.now());
            repository.save(pf);
        }
    }

    @Transactional(readOnly = true)
    public boolean isProtected(String filePath) {
        return repository.existsByFilePathAndActiveTrue(filePath);
    }

    @Transactional(readOnly = true)
    public List<ProtectedFile> getAllProtectedFiles() {
        return repository.findByActiveTrue();
    }

    @Transactional(readOnly = true)
    public Optional<ProtectedFile> getProtectedFile(String filePath) {
        return repository.findByFilePath(filePath);
    }

    @Transactional
    public void initializeDefaultProtectedFiles() {
        String[] criticalFiles = {
                "C:\\Windows\\System32\\ntoskrnl.exe",
                "C:\\Windows\\System32\\ntdll.dll",
                "C:\\Windows\\System32\\kernel32.dll",
                "C:\\Windows\\System32\\kernelbase.dll",
                "C:\\Windows\\System32\\user32.dll",
                "C:\\Windows\\System32\\advapi32.dll",
                "C:\\Windows\\System32\\msvcrt.dll",
                "C:\\Windows\\System32\\sechost.dll",
                "C:\\Windows\\System32\\rpcrt4.dll",
                "C:\\Windows\\System32\\lsass.exe",
                "C:\\Windows\\System32\\services.exe",
                "C:\\Windows\\System32\\wininit.exe",
                "C:\\Windows\\System32\\csrss.exe",
                "C:\\Windows\\System32\\smss.exe",
                "C:\\Windows\\System32\\winlogon.exe",
                "C:\\Windows\\System32\\spoolsv.exe",
                "C:\\Windows\\System32\\taskhost.exe",
                "C:\\Windows\\System32\\dwm.exe",
                "C:\\Windows\\explorer.exe"
        };

        for (String file : criticalFiles) {
            if (!repository.existsByFilePathAndActiveTrue(file)) {
                repository.save(new ProtectedFile(file, "Critical Windows system file"));
            }
        }
    }
}