package com.pki.example.data;

import com.pki.example.data.User;
import lombok.Getter; import lombok.NoArgsConstructor; import lombok.Setter;

import javax.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "ca_secrets", uniqueConstraints = {
        @UniqueConstraint(name = "uk_ca_user", columnNames = {"ca_user_id"})
})
@Getter @Setter @NoArgsConstructor
public class CaSecret {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ca_user_id", nullable = false)
    private User caUser;

    @Lob @Column(name = "kek_enc", nullable = false)
    private byte[] kekEnc;

    @Column(name = "kek_iv", nullable = false, length = 32)
    private byte[] kekIv;

    @Column(name = "kek_version", nullable = false)
    private Integer kekVersion = 1;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();
}
