package com.pki.example.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")		// dozvoljava cross-origin zahteve ka svim API endpoint-ima
                .allowedOrigins("https://localhost:4200")	// postavice Access-Control-Allow-Origin header u preflight zahtev
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)		// dozvoljava slanje cookies i authorization headers
                .maxAge(3600);		// definise u sekundama koliko dugo se preflight response cuva u browseru
                
        registry.addMapping("/auth/**")		// zadržavamo i postojeće mapiranje za auth endpoint-e
                .allowedOrigins("https://localhost:4200")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowedHeaders("*")
                .allowCredentials(true)
                .maxAge(3600);
    }

}
