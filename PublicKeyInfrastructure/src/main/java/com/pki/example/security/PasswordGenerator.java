package com.pki.example.security;

import com.nulabinc.zxcvbn.Strength;
import com.nulabinc.zxcvbn.Zxcvbn;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class PasswordGenerator {
    private static final Zxcvbn zxcvbn = new Zxcvbn();
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()-_=+[]{};:,.<>?/";

    private static final String ALL = UPPER + LOWER + DIGITS + SPECIAL;
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String generatePassword(int length) {
        if (length < 4) {
            throw new IllegalArgumentException("Password length must be at least 4 characters.");
        }

        List<Character> passwordChars = new ArrayList<>(length);

        passwordChars.add(randomCharFrom(UPPER));
        passwordChars.add(randomCharFrom(LOWER));
        passwordChars.add(randomCharFrom(DIGITS));
        passwordChars.add(randomCharFrom(SPECIAL));

        for (int i = 4; i < length; i++) {
            passwordChars.add(randomCharFrom(ALL));
        }

        Collections.shuffle(passwordChars, RANDOM);

        StringBuilder sb = new StringBuilder(length);
        for (char c : passwordChars) {
            sb.append(c);
        }

        return sb.toString();
    }

    private static char randomCharFrom(String chars) {
        int idx = RANDOM.nextInt(chars.length());
        return chars.charAt(idx);
    }
    public static boolean isPasswordStrongEnough(String password) {
        Strength strength = zxcvbn.measure(password);
        return strength.getScore() >= 3;
    }
}

