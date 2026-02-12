package com.pki.example.data;

public enum ExtendedKeyUsage {
    SERVER_AUTH,      // TLS Web Server Authentication
    CLIENT_AUTH,      // TLS Web Client Authentication
    CODE_SIGNING,     // Potpisivanje softvera
    EMAIL_PROTECTION, // S/MIME
    TIME_STAMPING,    // Time Stamping
    OCSP_SIGNING,     // OCSP Responder
    SMARTCARD_LOGON   // (MS EKU) Smartcard Logon – opciono
}
