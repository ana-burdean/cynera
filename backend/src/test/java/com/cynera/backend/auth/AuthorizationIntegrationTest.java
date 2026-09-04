package com.cynera.backend.auth;

import com.cynera.backend.auth.entity.User;
import com.cynera.backend.auth.repository.UserRepository;
import com.cynera.backend.auth.security.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @BeforeEach
    void cleanDatabase() {
        userRepository.deleteAll();
    }

    @Test
    void protectedEndpointShouldRejectRequestWithoutJwt()
            throws Exception {

        mockMvc.perform(
                        get("/api/v1/events")
                )
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointShouldAcceptValidJwt()
            throws Exception {

        User user = new User(
                "alice",
                passwordEncoder.encode("password123"),
                true
        );

        userRepository.save(user);

        String token =
                jwtService.generateToken("alice");

        mockMvc.perform(
                        get("/api/v1/events")
                                .header(
                                        "Authorization",
                                        "Bearer " + token
                                )
                )
                .andExpect(status().isOk());
    }

    @Test
    void healthEndpointShouldRemainPublic()
            throws Exception {

        mockMvc.perform(
                        get("/actuator/health")
                )
                .andExpect(status().isOk());
    }
}