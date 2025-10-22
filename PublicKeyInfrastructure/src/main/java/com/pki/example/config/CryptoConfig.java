package com.pki.example.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Configuration
public class CryptoConfig {

    @Value("${app.master.secret}")
    private String appSecret;

    @Bean
    public SecretKey masterKey() {
        try {
            byte[] salt = "pki-app-salt-v1".getBytes(StandardCharsets.UTF_8);
            PBEKeySpec spec = new PBEKeySpec(appSecret.toCharArray(), salt, 200_000, 256);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = skf.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 derive failed", e);
        }
    }
}
