package com.cynera.backend.auth.repository;

import com.cynera.backend.auth.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    void shouldSaveAndFindUserByUsername() {
        User user = new User(
                "ana",
                "hashed-password",
                true
        );

        userRepository.save(user);

        User found = userRepository
                .findByUsername("ana")
                .orElseThrow();

        assertNotNull(found.getId());
        assertEquals("ana", found.getUsername());
        assertEquals("hashed-password", found.getPassword());
        assertTrue(found.isEnabled());
    }

    @Test
    void shouldCheckIfUsernameExists() {
        User user = new User(
                "ana",
                "hashed-password",
                true
        );

        userRepository.save(user);

        assertTrue(
                userRepository.existsByUsername("ana")
        );

        assertFalse(
                userRepository.existsByUsername("unknown")
        );
    }
}