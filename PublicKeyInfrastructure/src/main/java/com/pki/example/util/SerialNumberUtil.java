package com.pki.example.util;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SerialNumberUtil {
    private static final SecureRandom RNG = new SecureRandom();

    /** Generiše pozitivan, nasumičan serijski broj od ~160 bita. */
    public static BigInteger generateSerial160() {
        byte[] bytes = new byte[20];      // 20 bajtova = 160 bita
        RNG.nextBytes(bytes);
        return toPositiveBigInteger(bytes);
    }

    /** Generiše pozitivan serijski broj sa zadatim brojem bitova (npr. 128, 160, 256). */
    public static BigInteger generateSerial(int bits) {
        if (bits < 32) throw new IllegalArgumentException("bits too small");
        int len = (bits + 7) / 8;
        byte[] bytes = new byte[len];
        RNG.nextBytes(bytes);
        return toPositiveBigInteger(bytes);
    }

    /** Pretvara bajtove u pozitivan BigInteger, izbegava negativan sign-bit. */
    private static BigInteger toPositiveBigInteger(byte[] bytes) {
        // Čistija varijanta od maskiranja: '1' znači pozitivan broj
        BigInteger bi = new BigInteger(1, bytes);
        // Osiguraj da nije nula (teorijski vrlo retko)
        if (bi.signum() == 0) {
            // ponovno bacanje kocke za jedan bajt
            byte[] b = new byte[1];
            RNG.nextBytes(b);
            return new BigInteger(1, b);
        }
        return bi;
    }

    /** (Opcionalno) heks string ako ti treba kao tekstualni serial u certu/logu. */
    public static String toHex(BigInteger serial) {
        return serial.toString(16).toUpperCase();
    }
}
