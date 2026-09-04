package com.cynera.backend.auth.controller;

import com.cynera.backend.auth.dto.LoginRequest;
import com.cynera.backend.auth.dto.RegisterRequest;
import com.cynera.backend.auth.entity.User;
import com.cynera.backend.auth.security.JwtService;
import com.cynera.backend.auth.service.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private UserService userService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthController authController;

    @Test
    void registerShouldCreateUserAndReturnToken() {
        RegisterRequest request =
                new RegisterRequest("alice", "password");

        User user =
                new User("alice", "encoded-password", true);

        when(passwordEncoder.encode("password"))
                .thenReturn("encoded-password");

        when(userService.createUser(
                "alice",
                "encoded-password"
        )).thenReturn(user);

        when(jwtService.generateToken("alice"))
                .thenReturn("jwt-token");

        var response = authController.register(request);

        assertEquals(HttpStatus.CREATED, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("jwt-token", response.getBody().token());

        verify(passwordEncoder)
                .encode("password");

        verify(userService)
                .createUser("alice", "encoded-password");

        verify(jwtService)
                .generateToken("alice");
    }

    @Test
    void loginShouldReturnTokenForValidCredentials() {
        LoginRequest request =
                new LoginRequest("alice", "password");

        User user =
                new User("alice", "encoded-password", true);

        when(userService.findByUsername("alice"))
                .thenReturn(user);

        when(passwordEncoder.matches(
                "password",
                "encoded-password"
        )).thenReturn(true);

        when(jwtService.generateToken("alice"))
                .thenReturn("jwt-token");

        var response = authController.login(request);

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertNotNull(response.getBody());
        assertEquals("jwt-token", response.getBody().token());

        verify(userService)
                .findByUsername("alice");

        verify(passwordEncoder)
                .matches("password", "encoded-password");

        verify(jwtService)
                .generateToken("alice");
    }

    @Test
    void loginShouldRejectInvalidPassword() {
        LoginRequest request =
                new LoginRequest("alice", "wrong-password");

        User user =
                new User("alice", "encoded-password", true);

        when(userService.findByUsername("alice"))
                .thenReturn(user);

        when(passwordEncoder.matches(
                "wrong-password",
                "encoded-password"
        )).thenReturn(false);

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> authController.login(request)
                );

        assertEquals(
                "Invalid username or password",
                exception.getMessage()
        );

        verify(jwtService, never())
                .generateToken(anyString());
    }

    @Test
    void loginShouldRejectDisabledUser() {
        LoginRequest request =
                new LoginRequest("alice", "password");

        User user =
                new User("alice", "encoded-password", false);

        when(userService.findByUsername("alice"))
                .thenReturn(user);

        when(passwordEncoder.matches(
                "password",
                "encoded-password"
        )).thenReturn(true);

        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> authController.login(request)
                );

        assertEquals(
                "User is disabled",
                exception.getMessage()
        );

        verify(jwtService, never())
                .generateToken(anyString());
    }
}