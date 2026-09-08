package com.cynera.backend;

import com.cynera.backend.detection.ransomware.PreventionService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class BackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(BackendApplication.class, args);
    }

    @Bean
    CommandLineRunner initPrevention(ObjectProvider<PreventionService> preventionServiceProvider) {
        return args -> preventionServiceProvider.ifAvailable(
                PreventionService::initializeSystemProtection
        );
    }
}
