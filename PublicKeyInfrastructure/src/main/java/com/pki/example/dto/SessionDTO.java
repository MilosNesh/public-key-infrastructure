package com.pki.example.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.pki.example.data.SessionInfo;
import java.time.Instant;

public class SessionDTO {

    private String sid;
    private String ip;
    private String userAgent;
    private String deviceType;
    private String os;
    private String browser;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private Instant createdAt;
    @JsonFormat(shape = JsonFormat.Shape.STRING)
    private Instant lastActivityAt;
    private boolean revoked;

    public SessionDTO() {
    }

    public SessionDTO(String sid, String ip, String userAgent, String deviceType,
                      String os, String browser, Instant createdAt,
                      Instant lastActivityAt, boolean revoked) {
        this.sid = sid;
        this.ip = ip;
        this.userAgent = userAgent;
        this.deviceType = deviceType;
        this.os = os;
        this.browser = browser;
        this.createdAt = createdAt;
        this.lastActivityAt = lastActivityAt;
        this.revoked = revoked;
    }

    public static SessionDTO from(SessionInfo s) {
        return new SessionDTO(
                s.getSid(),
                s.getIp(),
                s.getUserAgent(),
                s.getDeviceType(),
                s.getOs(),
                s.getBrowser(),
                s.getCreatedAt(),
                s.getLastActivityAt(),
                s.isRevoked()
        );
    }

    // Getteri i setteri
    public String getSid() { return sid; }
    public void setSid(String sid) { this.sid = sid; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public String getDeviceType() { return deviceType; }
    public void setDeviceType(String deviceType) { this.deviceType = deviceType; }

    public String getOs() { return os; }
    public void setOs(String os) { this.os = os; }

    public String getBrowser() { return browser; }
    public void setBrowser(String browser) { this.browser = browser; }

    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }

    public Instant getLastActivityAt() { return lastActivityAt; }
    public void setLastActivityAt(Instant lastActivityAt) { this.lastActivityAt = lastActivityAt; }

    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
}
