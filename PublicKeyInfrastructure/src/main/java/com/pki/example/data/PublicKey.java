package com.pki.example.data;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "publicKey")
public class PublicKey {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "userId", unique = true, nullable = false)
    private Long userId;
    @Column(name = "key", columnDefinition = "TEXT")
    private String key;

    public PublicKey(Long userId, String key) {
        this.userId = userId;
        this.key = key;
    }

    public boolean isValid() {
        return userId != null && key != null && !key.isEmpty() && userId > 0;
    }
}
