package com.pki.example.domain;

import com.pki.example.data.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Entity
@Table(name = "user_certificates")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserCertificate {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @Column(name = "certificate_id", nullable = false)
    private Long certificateId;
    
    @Column(name = "keystore_password", nullable = true, length = 255)
    private String keystorePassword;  // Plain text lozinka (TODO: šifrovati kasnije)
    
    @Column(name = "keystore_path", nullable = false, length = 500)
    private String keystorePath;

    public UserCertificate(User user, Long certificateId, String keystorePassword, String keystorePath) {
        this.user = user;
        this.certificateId = certificateId;
        this.keystorePassword = keystorePassword;
        this.keystorePath = keystorePath;
    }
}

