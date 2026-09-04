package com.cynera.backend.auth.security;

import com.cynera.backend.agent.security.AgentAuthenticationFilter;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.*;

class SecurityConfigTest {

    @Test
    void passwordEncoderShouldBeBCrypt() {

        SecurityConfig securityConfig =
                new SecurityConfig(
                        null,
                        null
                );

        PasswordEncoder passwordEncoder =
                securityConfig.passwordEncoder();

        assertNotNull(passwordEncoder);

        assertInstanceOf(
                BCryptPasswordEncoder.class,
                passwordEncoder
        );
    }

    @Test
    void passwordEncoderShouldEncodeAndMatchPassword() {

        SecurityConfig securityConfig =
                new SecurityConfig(
                        null,
                        null
                );

        PasswordEncoder passwordEncoder =
                securityConfig.passwordEncoder();

        String encoded =
                passwordEncoder.encode("password");

        assertNotEquals(
                "password",
                encoded
        );

        assertTrue(
                passwordEncoder.matches(
                        "password",
                        encoded
                )
        );

        assertFalse(
                passwordEncoder.matches(
                        "wrong-password",
                        encoded
                )
        );
    }

    @Test
    void securityConfigShouldAcceptAgentAuthenticationFilter() {

        AgentAuthenticationFilter agentAuthenticationFilter =
                null;

        SecurityConfig securityConfig =
                new SecurityConfig(
                        null,
                        agentAuthenticationFilter
                );

        assertNotNull(securityConfig);
    }
}