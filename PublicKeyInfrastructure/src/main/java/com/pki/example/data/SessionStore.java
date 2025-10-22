package com.pki.example.data;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface SessionStore {
    void save(SessionInfo s);
    Optional<SessionInfo> find(String userId, String sid);
    List<SessionInfo> findAllByUser(String userId);
    void touch(String userId, String sid, Instant when, String ip, String ua);
    void revoke(String userId, String sid);
    void delete(String userId, String sid);
}
