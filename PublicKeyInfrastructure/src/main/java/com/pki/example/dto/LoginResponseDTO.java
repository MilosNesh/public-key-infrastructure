package com.pki.example.dto;

public class LoginResponseDTO {
    private String token;
    private boolean mustChangePassword;

    public LoginResponseDTO(String token, boolean mustChangePassword) {
        this.token = token;
        this.mustChangePassword = mustChangePassword;
    }

    public String getToken() {
        return token;
    }

    public boolean getMustChangePassword() {
        return mustChangePassword;
    }
}

