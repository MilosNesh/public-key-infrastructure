// src/main/java/com/pki/example/util/ClientInfo.java
package com.pki.example.util;

import org.springframework.stereotype.Component;
import ua_parser.Client;
import ua_parser.Parser;

import javax.servlet.http.HttpServletRequest;

@Component
public class ClientInfo {

    private static final Parser PARSER = initParser();

    private static Parser initParser() {
        return new Parser();
    }

    public String extractIp(HttpServletRequest req) {
        String ip = req.getHeader("X-Forwarded-For");
        if (ip != null && !ip.isBlank()) {
            if (ip.contains(",")) ip = ip.split(",")[0].trim();
            return normalizeLoopback(ip);
        }
        return normalizeLoopback(req.getRemoteAddr());
    }

    public ParsedUA parseUA(String userAgent) {
        Client c = PARSER.parse(userAgent == null ? "" : userAgent);
        String browser = (c.userAgent != null && c.userAgent.family != null) ? c.userAgent.family : "Web Browser";
        String os      = (c.os != null && c.os.family != null) ? c.os.family : "Unknown OS";
        String device  = (c.device != null && c.device.family != null) ? c.device.family : "Other";
        String deviceType = "Other".equalsIgnoreCase(device) ? "Desktop" : device;
        return new ParsedUA(browser, os, deviceType);
    }

    private String normalizeLoopback(String ip) {
        if ("0:0:0:0:0:0:0:1".equals(ip) || "::1".equals(ip)) return "127.0.0.1";
        return ip;
    }

    public static class ParsedUA {
        private final String browser;
        private final String os;
        private final String deviceType;

        public ParsedUA(String browser, String os, String deviceType) {
            this.browser = browser;
            this.os = os;
            this.deviceType = deviceType;
        }

        public String browser()    { return browser; }
        public String os()         { return os; }
        public String deviceType() { return deviceType; }
    }
}
