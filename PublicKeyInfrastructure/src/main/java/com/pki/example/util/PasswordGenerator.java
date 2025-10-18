package com.pki.example.util;

import java.security.SecureRandom;

public class PasswordGenerator {

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_CHARS = "!@#$%^&*()-_=+[]{}";
    private static final String ALL_CHARS = UPPERCASE + LOWERCASE + DIGITS + SPECIAL_CHARS;
    
    private static final SecureRandom random = new SecureRandom();

    /**
     * Generiše random lozinku sa zadatom dužinom
     * @param length Dužina lozinke
     * @return Random lozinka
     */
    public static String generatePassword(int length) {
        if (length < 8) {
            throw new IllegalArgumentException("Lozinka mora biti najmanje 8 karaktera");
        }

        StringBuilder password = new StringBuilder(length);
        
        // Garantujemo da ima bar po jedan karakter svake vrste
        password.append(UPPERCASE.charAt(random.nextInt(UPPERCASE.length())));
        password.append(LOWERCASE.charAt(random.nextInt(LOWERCASE.length())));
        password.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
        password.append(SPECIAL_CHARS.charAt(random.nextInt(SPECIAL_CHARS.length())));
        
        // Popunjavamo ostatak random karakterima
        for (int i = 4; i < length; i++) {
            password.append(ALL_CHARS.charAt(random.nextInt(ALL_CHARS.length())));
        }
        
        // Mešamo karaktere
        return shuffleString(password.toString());
    }

    /**
     * Generiše random lozinku default dužine (16 karaktera)
     */
    public static String generatePassword() {
        return generatePassword(16);
    }

    /**
     * Meša karaktere u stringu
     */
    private static String shuffleString(String input) {
        char[] chars = input.toCharArray();
        for (int i = chars.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = chars[i];
            chars[i] = chars[j];
            chars[j] = temp;
        }
        return new String(chars);
    }
}



