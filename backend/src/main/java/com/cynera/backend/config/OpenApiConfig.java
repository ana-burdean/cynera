package com.cynera.backend.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI cyneraOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Cynera API")
                        .version("0.1.0")
                        .description(
                                "API for the Cynera lightweight Endpoint "
                                        + "Detection and Response system."
                        )
                );
    }
}