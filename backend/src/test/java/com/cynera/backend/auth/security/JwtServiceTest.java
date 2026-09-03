package com.cynera.backend.auth.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    private static final String SECRET =
            "cynera-development-secret-key-2026-change-me";

    private static final long EXPIRATION_MS =
            86_400_000L;

    @Test
    void shouldGenerateTokenAndExtractUsername() {
        JwtService jwtService =
                new JwtService(SECRET, EXPIRATION_MS);

        String token =
                jwtService.generateToken("ana");

        assertNotNull(token);
        assertFalse(token.isBlank());

        assertEquals(
                "ana",
                jwtService.extractUsername(token)
        );
    }

    @Test
    void shouldValidateCorrectToken() {
        JwtService jwtService =
                new JwtService(SECRET, EXPIRATION_MS);

        String token =
                jwtService.generateToken("ana");

        assertTrue(
                jwtService.isTokenValid(token, "ana")
        );
    }

    @Test
    void shouldRejectTokenForDifferentUsername() {
        JwtService jwtService =
                new JwtService(SECRET, EXPIRATION_MS);

        String token =
                jwtService.generateToken("ana");

        assertFalse(
                jwtService.isTokenValid(token, "other-user")
        );
    }
}
