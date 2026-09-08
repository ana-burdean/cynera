package com.cynera.backend.detection.ransomware;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ProtectedFileRepository extends JpaRepository<ProtectedFile, Long> {

    Optional<ProtectedFile> findByFilePath(String filePath);

    List<ProtectedFile> findByActiveTrue();

    boolean existsByFilePathAndActiveTrue(String filePath);
}