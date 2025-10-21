package com.pki.example.data;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "sharedPassword")
public class SharedPassword {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "passwordId")
    private Long passwordId;

    @Column(name = "password", columnDefinition = "TEXT")
    private String password;

    @Column(name = "userId")
    private Long userId;

    public SharedPassword(Long passwordId, String password, Long userId) {
        this.password = password;
        this.userId = userId;
        this.passwordId = passwordId;
    }

    public boolean isValid(){
        return passwordId != null && password != null && userId != null && !password.isEmpty();
    }
}
