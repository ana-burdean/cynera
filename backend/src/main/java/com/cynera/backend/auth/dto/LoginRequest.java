package com.cynera.backend.auth.dto;

public record LoginRequest(
        String username,
        String password
) {
}