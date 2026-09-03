package com.cynera.backend.auth.controller;

import com.cynera.backend.auth.dto.AuthResponse;
import com.cynera.backend.auth.dto.LoginRequest;
import com.cynera.backend.auth.dto.RegisterRequest;
import com.cynera.backend.auth.entity.User;
import com.cynera.backend.auth.security.JwtService;
import com.cynera.backend.auth.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    public AuthController(
            UserService userService,
            PasswordEncoder passwordEncoder,
            JwtService jwtService
    ) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @RequestBody RegisterRequest request
    ) {
        User user = userService.createUser(
                request.username(),
                passwordEncoder.encode(request.password())
        );

        String token = jwtService.generateToken(
                user.getUsername()
        );

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(new AuthResponse(token));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @RequestBody LoginRequest request
    ) {
        User user = userService.findByUsername(
                request.username()
        );

        if (!passwordEncoder.matches(
                request.password(),
                user.getPassword()
        )) {
            throw new IllegalArgumentException(
                    "Invalid username or password"
            );
        }

        if (!user.isEnabled()) {
            throw new IllegalArgumentException(
                    "User is disabled"
            );
        }

        String token = jwtService.generateToken(
                user.getUsername()
        );

        return ResponseEntity.ok(
                new AuthResponse(token)
        );
    }
}