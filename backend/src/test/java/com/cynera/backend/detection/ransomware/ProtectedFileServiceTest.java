package com.cynera.backend.detection.ransomware;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ProtectedFileServiceTest {

    @Mock
    private ProtectedFileRepository repository;

    @InjectMocks
    private ProtectedFileService protectedFileService;

    @BeforeEach
    void setUp() {
        lenient().when(repository.findByFilePath(anyString())).thenReturn(Optional.empty());
    }

    @Test
    void shouldProtectFile() {
        when(repository.save(any(ProtectedFile.class))).thenAnswer(inv -> inv.getArgument(0));

        ProtectedFile result = protectedFileService.protectFile("C:\\test.exe", "Test file");

        assertEquals("C:\\test.exe", result.getFilePath());
        assertEquals("Test file", result.getDescription());
        assertTrue(result.isActive());
        assertNotNull(result.getCreatedAt());
        verify(repository).save(any(ProtectedFile.class));
    }

    @Test
    void shouldThrowWhenFileAlreadyProtected() {
        ProtectedFile existing = new ProtectedFile("C:\\test.exe", "Existing");
        when(repository.findByFilePath("C:\\test.exe")).thenReturn(Optional.of(existing));

        assertThrows(IllegalArgumentException.class, () -> 
            protectedFileService.protectFile("C:\\test.exe", "Test file")
        );
    }

    @Test
    void shouldReactivatePreviouslyUnprotectedFile() {
        ProtectedFile existing = new ProtectedFile("C:\\test.exe", "Old description");
        existing.setActive(false);

        when(repository.findByFilePath("C:\\test.exe"))
                .thenReturn(Optional.of(existing));
        when(repository.save(any(ProtectedFile.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        ProtectedFile result = protectedFileService.protectFile(
                "C:\\test.exe",
                "Reactivated file"
        );

        assertSame(existing, result);
        assertTrue(result.isActive());
        assertEquals("Reactivated file", result.getDescription());
        assertNotNull(result.getUpdatedAt());
        verify(repository).save(existing);
    }

    @Test
    void shouldUnprotectFile() {
        ProtectedFile pf = new ProtectedFile("C:\\test.exe", "Test");
        when(repository.findByFilePath("C:\\test.exe")).thenReturn(Optional.of(pf));
        when(repository.save(any(ProtectedFile.class))).thenAnswer(inv -> inv.getArgument(0));

        protectedFileService.unprotectFile("C:\\test.exe");

        assertFalse(pf.isActive());
        assertNotNull(pf.getUpdatedAt());
        verify(repository).save(pf);
    }

    @Test
    void shouldHandleUnprotectNonExistentFile() {
        when(repository.findByFilePath("C:\\nonexistent.exe")).thenReturn(Optional.empty());

        protectedFileService.unprotectFile("C:\\nonexistent.exe");

        verify(repository, never()).save(any());
    }

    @Test
    void shouldCheckIfProtected() {
        when(repository.existsByFilePathAndActiveTrue("C:\\test.exe"))
                .thenReturn(true);

        assertTrue(protectedFileService.isProtected("C:\\test.exe"));
    }

    @Test
    void shouldReturnAllProtectedFiles() {
        ProtectedFile pf1 = new ProtectedFile("C:\\a.exe", "File A");
        ProtectedFile pf2 = new ProtectedFile("C:\\b.exe", "File B");
        when(repository.findByActiveTrue()).thenReturn(List.of(pf1, pf2));

        List<ProtectedFile> result = protectedFileService.getAllProtectedFiles();

        assertEquals(2, result.size());
    }

    @Test
    void shouldInitializeDefaultProtectedFiles() {
        when(repository.existsByFilePathAndActiveTrue(anyString())).thenReturn(false);
        when(repository.save(any(ProtectedFile.class))).thenAnswer(inv -> inv.getArgument(0));

        protectedFileService.initializeDefaultProtectedFiles();

        verify(repository, atLeast(19)).save(any(ProtectedFile.class));
    }
}