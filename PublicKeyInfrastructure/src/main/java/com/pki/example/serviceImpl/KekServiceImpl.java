package com.pki.example.serviceImpl;

import com.pki.example.data.CaSecret;
import com.pki.example.repository.CaSecretRepository;
import com.pki.example.data.User;
import com.pki.example.service.KekService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class KekServiceImpl implements KekService {

    private final CaSecretRepository repo;
    private final AesGcmService aes;

    private static final byte[] AAD = "ca_user_kek".getBytes(StandardCharsets.UTF_8);

    @Transactional
    public SecretKey getOrCreateKek(long caUserId) {
        var opt = repo.findByCaUserId(caUserId);
        if (opt.isEmpty()) {
            byte[] kek = new byte[32];
            new SecureRandom().nextBytes(kek);
            var blob = aes.encryptBytes(kek, AAD); // enkripcija MASTER ključem

            var cs = new CaSecret();
            var u = new User(); u.setId(caUserId); // attach by id
            cs.setCaUser(u);
            cs.setKekEnc(blob.getCt());
            cs.setKekIv(blob.getIv());
            cs.setKekVersion(1);
            repo.save(cs);

            return new SecretKeySpec(kek, "AES");
        } else {
            CaSecret cs = opt.get();
            byte[] kek = aes.decryptBytes(cs.getKekIv(), cs.getKekEnc(), AAD);
            return new SecretKeySpec(kek, "AES");
        }
    }
}
