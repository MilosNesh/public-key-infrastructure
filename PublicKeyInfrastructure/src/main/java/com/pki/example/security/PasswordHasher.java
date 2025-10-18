package com.pki.example.security;

import org.springframework.security.crypto.bcrypt.BCrypt;

public class PasswordHasher {

    private static final int COST = 12;

    public static String hashPassword(String plainPassword) {
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt(COST));
    }

    public static boolean verifyPassword(String plainPassword, String hashedPassword) {
        return BCrypt.checkpw(plainPassword, hashedPassword);
    }
}