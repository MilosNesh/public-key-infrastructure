package com.pki.example.dto;

import com.pki.example.data.Password;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class PasswordDTO {
    private String siteName;
    public String username;
    private String password;

    public PasswordDTO(Password password) {
        this.siteName = password.getSiteName();
        this.username = password.getUsername();
        this.password = password.getPassword();
    }
}
