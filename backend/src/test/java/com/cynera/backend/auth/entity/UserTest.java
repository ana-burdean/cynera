package com.cynera.backend.auth.entity;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    @Test
    void shouldCreateEnabledUser() {
        User user = new User(
                "ana",
                "hashed-password",
                true
        );

        assertEquals("ana", user.getUsername());
        assertEquals("hashed-password", user.getPassword());
        assertTrue(user.isEnabled());
    }

    @Test
    void shouldCreateDisabledUser() {
        User user = new User(
                "ana",
                "hashed-password",
                false
        );

        assertFalse(user.isEnabled());
    }

    @Test
    void idShouldBeNullBeforePersistence() {
        User user = new User(
                "ana",
                "hashed-password",
                true
        );

        assertNull(user.getId());
    }
}
