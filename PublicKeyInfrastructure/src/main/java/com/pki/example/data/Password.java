package com.pki.example.data;

import com.pki.example.dto.PasswordDTO;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "passwords")
public class Password {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "password", columnDefinition = "TEXT")
    private String password;
    @Column(name = "siteName")
    private String siteName;
    @Column(name = "username")
    private String username;
    @Column(name = "userId")
    private Long userId;

    public Password(String password, String siteName, String username, Long userId) {
        this.password = password;
        this.siteName = siteName;
        this.username = username;
        this.userId = userId;
    }

    public Password(PasswordDTO passwordDTO) {
        this.password = passwordDTO.getPassword();
        this.siteName = passwordDTO.getSiteName();
        this.username = passwordDTO.getUsername();
    }
    public boolean isValid() {
        return password != null && userId != null && siteName != null && username != null && password.length() > 0 && userId > 0 && !username.isEmpty() && !password.isEmpty() && !siteName.isEmpty();
    }
}
