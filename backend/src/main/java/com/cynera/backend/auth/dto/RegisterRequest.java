package com.cynera.backend.auth.dto;

public record RegisterRequest(
        String username,
        String password
) {
}