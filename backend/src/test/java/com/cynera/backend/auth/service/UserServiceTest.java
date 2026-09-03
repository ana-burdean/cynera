package com.cynera.backend.auth.service;

import com.cynera.backend.auth.entity.User;
import com.cynera.backend.auth.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    @Test
    void shouldCreateUser() {
        User user = new User(
                "ana",
                "hashed-password",
                true
        );

        when(userRepository.existsByUsername("ana"))
                .thenReturn(false);

        when(userRepository.save(any(User.class)))
                .thenReturn(user);

        User result = userService.createUser(
                "ana",
                "hashed-password"
        );

        assertEquals("ana", result.getUsername());
        assertEquals("hashed-password", result.getPassword());
        assertTrue(result.isEnabled());

        verify(userRepository).save(any(User.class));
    }

    @Test
    void shouldRejectDuplicateUsername() {
        when(userRepository.existsByUsername("ana"))
                .thenReturn(true);

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> userService.createUser(
                                "ana",
                                "hashed-password"
                        )
                );

        assertTrue(
                exception.getMessage()
                        .contains("Username already exists")
        );

        verify(userRepository, never())
                .save(any(User.class));
    }

    @Test
    void shouldFindUserByUsername() {
        User user = new User(
                "ana",
                "hashed-password",
                true
        );

        when(userRepository.findByUsername("ana"))
                .thenReturn(Optional.of(user));

        User result = userService.findByUsername("ana");

        assertEquals("ana", result.getUsername());
    }

    @Test
    void shouldThrowWhenUserDoesNotExist() {
        when(userRepository.findByUsername("unknown"))
                .thenReturn(Optional.empty());

        assertThrows(
                IllegalArgumentException.class,
                () -> userService.findByUsername("unknown")
        );
    }
}
