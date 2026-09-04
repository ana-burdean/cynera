package com.cynera.backend.auth.security;

import com.cynera.backend.auth.entity.User;
import com.cynera.backend.auth.service.UserService;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserService userService;

    @Mock
    private FilterChain filterChain;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void shouldContinueWithoutAuthenticationWhenHeaderIsMissing()
            throws Exception {

        JwtAuthenticationFilter filter =
                new JwtAuthenticationFilter(
                        jwtService,
                        userService
                );

        MockHttpServletRequest request =
                new MockHttpServletRequest();

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain)
                .doFilter(request, response);

        verifyNoInteractions(jwtService);
        verifyNoInteractions(userService);

        assertNull(
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
        );
    }

    @Test
    void shouldAuthenticateValidToken() throws Exception {
        JwtAuthenticationFilter filter =
                new JwtAuthenticationFilter(
                        jwtService,
                        userService
                );

        MockHttpServletRequest request =
                new MockHttpServletRequest();

        request.addHeader(
                "Authorization",
                "Bearer valid-token"
        );

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        User user =
                new User(
                        "alice",
                        "encoded-password",
                        true
                );

        when(jwtService.extractUsername("valid-token"))
                .thenReturn("alice");

        when(userService.findByUsername("alice"))
                .thenReturn(user);

        when(jwtService.isTokenValid(
                "valid-token",
                "alice"
        )).thenReturn(true);

        SecurityContextHolder.clearContext();

        filter.doFilter(request, response, filterChain);

        assertNotNull(
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
        );

        assertEquals(
                "alice",
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
                        .getName()
        );

        verify(filterChain)
                .doFilter(request, response);
    }

    @Test
    void shouldNotAuthenticateDisabledUser() throws Exception {
        JwtAuthenticationFilter filter =
                new JwtAuthenticationFilter(
                        jwtService,
                        userService
                );

        MockHttpServletRequest request =
                new MockHttpServletRequest();

        request.addHeader(
                "Authorization",
                "Bearer valid-token"
        );

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        User user =
                new User(
                        "alice",
                        "encoded-password",
                        false
                );

        when(jwtService.extractUsername("valid-token"))
                .thenReturn("alice");

        when(userService.findByUsername("alice"))
                .thenReturn(user);

        SecurityContextHolder.clearContext();

        filter.doFilter(request, response, filterChain);

        assertNull(
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
        );

        verify(filterChain)
                .doFilter(request, response);
    }

    @Test
    void shouldContinueWithoutAuthenticationForInvalidToken()
            throws Exception {

        JwtAuthenticationFilter filter =
                new JwtAuthenticationFilter(
                        jwtService,
                        userService
                );

        MockHttpServletRequest request =
                new MockHttpServletRequest();

        request.addHeader(
                "Authorization",
                "Bearer invalid-token"
        );

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        when(jwtService.extractUsername("invalid-token"))
                .thenThrow(new RuntimeException("Invalid JWT"));

        SecurityContextHolder.clearContext();

        filter.doFilter(request, response, filterChain);

        assertNull(
                SecurityContextHolder
                        .getContext()
                        .getAuthentication()
        );

        verify(filterChain)
                .doFilter(request, response);
    }
}