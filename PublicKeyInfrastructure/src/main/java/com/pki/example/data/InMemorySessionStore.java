package com.pki.example.data;

import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Repository
public class InMemorySessionStore implements SessionStore {
    private final Map<String, SessionInfo> map = new ConcurrentHashMap<>();
    private String key(String u, String s){ return u + "::" + s; }

    @Override public void save(SessionInfo s){ map.put(key(s.getUserId(), s.getSid()), s); }
    @Override public Optional<SessionInfo> find(String u, String s){ return Optional.ofNullable(map.get(key(u,s))); }
    @Override public List<SessionInfo> findAllByUser(String u){
        return map.values().stream().filter(si -> si.getUserId().equals(u)).collect(Collectors.toList());
    }
    @Override public void touch(String u, String s, Instant t, String ip, String ua){
        find(u,s).ifPresent(si -> {
            si.setLastActivityAt(t);
            if (ip != null) si.setIp(ip);
            if (ua != null) si.setUserAgent(ua);
        });
    }
    @Override public void revoke(String u, String s){ find(u,s).ifPresent(si -> si.setRevoked(true)); }
    @Override public void delete(String u, String s){ map.remove(key(u,s)); }
}
