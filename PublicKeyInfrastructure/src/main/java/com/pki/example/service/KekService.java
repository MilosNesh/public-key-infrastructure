package com.pki.example.service;

import javax.crypto.SecretKey;

public interface KekService {
    SecretKey getOrCreateKek(long caUserId);
}
