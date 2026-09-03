package com.cynera.backend.auth.service;

import com.cynera.backend.auth.entity.User;
import com.cynera.backend.auth.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User createUser(
            String username,
            String password
    ) {
        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException(
                    "Username already exists: " + username
            );
        }

        User user = new User(
                username,
                password,
                true
        );

        return userRepository.save(user);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException(
                        "User not found: " + username
                ));
    }
}