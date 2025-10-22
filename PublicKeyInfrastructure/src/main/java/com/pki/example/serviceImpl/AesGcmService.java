package com.pki.example.serviceImpl;

import lombok.Getter;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class AesGcmService {
    private static final String XFORM = "AES/GCM/NoPadding";
    private static final int IV_LEN = 12; // 96-bit
    private static final int TAG_BITS = 128;

    private final SecretKey masterKey;
    private final SecureRandom rng = new SecureRandom();

    public AesGcmService(SecretKey masterKey) {
        this.masterKey = masterKey;
    }

    public String encryptToToken(String plaintext, String aadContext) {
        try {
            byte[] iv = new byte[IV_LEN];
            rng.nextBytes(iv);

            Cipher c = Cipher.getInstance(XFORM);
            c.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            if (aadContext != null) c.updateAAD(aadContext.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return "v1:" + Base64.getEncoder().encodeToString(iv) + ":" +
                    Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encrypt failed", e);
        }
    }

    public String decryptFromToken(String token, String aadContext) {
        try {
            if (token == null || token.isBlank()) return null;
            String[] parts = token.split(":");
            if (parts.length != 3 || !"v1".equals(parts[0])) {
                throw new IllegalArgumentException("Bad token format/version");
            }
            byte[] iv = Base64.getDecoder().decode(parts[1]);
            byte[] ct = Base64.getDecoder().decode(parts[2]);

            Cipher c = Cipher.getInstance(XFORM);
            c.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            if (aadContext != null) c.updateAAD(aadContext.getBytes(StandardCharsets.UTF_8));
            byte[] pt = c.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM decrypt failed", e);
        }
    }

    public EncBlob encryptBytes(byte[] plaintext, byte[] aad) {
        try {
            byte[] iv = new byte[IV_LEN];
            rng.nextBytes(iv);

            Cipher c = Cipher.getInstance(XFORM);
            c.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) c.updateAAD(aad);
            byte[] ct = c.doFinal(plaintext);
            return new EncBlob(iv, ct);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encryptBytes failed", e);
        }
    }

    public byte[] decryptBytes(byte[] iv, byte[] ciphertext, byte[] aad) {
        try {
            Cipher c = Cipher.getInstance(XFORM);
            c.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM decryptBytes failed", e);
        }
    }

    public String encryptToTokenWithKey(SecretKey key, String plaintext, String aadContext) {
        try {
            byte[] iv = new byte[IV_LEN];
            rng.nextBytes(iv);
            Cipher c = Cipher.getInstance(XFORM);
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            if (aadContext != null) c.updateAAD(aadContext.getBytes(StandardCharsets.UTF_8));
            byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return "v1:" + Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encryptWithKey failed", e);
        }
    }

    public String decryptFromTokenWithKey(SecretKey key, String token, String aadContext) {
        try {
            if (token == null || token.isBlank()) return null;
            String[] parts = token.split(":");
            if (parts.length != 3 || !"v1".equals(parts[0])) throw new IllegalArgumentException("Bad token");
            byte[] iv = Base64.getDecoder().decode(parts[1]);
            byte[] ct = Base64.getDecoder().decode(parts[2]);
            Cipher c = Cipher.getInstance(XFORM);
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            if (aadContext != null) c.updateAAD(aadContext.getBytes(StandardCharsets.UTF_8));
            byte[] pt = c.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM decryptWithKey failed", e);
        }
    }

    public EncBlob encryptBytesWithKey(SecretKey key, byte[] plaintext, byte[] aad) {
        try {
            byte[] iv = new byte[IV_LEN];
            rng.nextBytes(iv);
            Cipher c = Cipher.getInstance(XFORM);
            c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) c.updateAAD(aad);
            return new EncBlob(iv, c.doFinal(plaintext));
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encryptBytesWithKey failed", e);
        }
    }

    public byte[] decryptBytesWithKey(SecretKey key, byte[] iv, byte[] ciphertext, byte[] aad) {
        try {
            Cipher c = Cipher.getInstance(XFORM);
            c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            if (aad != null) c.updateAAD(aad);
            return c.doFinal(ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM decryptBytesWithKey failed", e);
        }
    }

    /** Jednostavan holder za (iv, ct) da ne vraćamo Map ili nizove. Radi na bilo kom JDK-u. */
    @Getter
    public static final class EncBlob {
        private final byte[] iv;
        private final byte[] ct;

        public EncBlob(byte[] iv, byte[] ct) { this.iv = iv; this.ct = ct; }
    }
}
