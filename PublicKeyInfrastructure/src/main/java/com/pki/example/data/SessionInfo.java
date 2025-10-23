package com.pki.example.data;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class SessionInfo {
    private String userId;
    private String sid;
    private String ip;
    private String userAgent;
    private String deviceType;
    private String os;
    private String browser;
    private Instant createdAt;
    private Instant lastActivityAt;
    private boolean revoked;
    private Instant expiresAt;
}
