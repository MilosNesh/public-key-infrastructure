-- Inicijalni podaci za User tabelu
INSERT INTO users (username, mail) VALUES ('admin', 'admin@example.com');

INSERT INTO csr_requests (user_id, certificate_id, csr_path, status, certificate_path)
VALUES (
           1,                                        -- user_id
           10,                                       -- certificate_id (npr. ID šablona ili CA sertifikata)
           'src/main/resources/csr/user_request.csr', -- putanja do CSR fajla
           'PENDING',                                -- trenutni status
           NULL                                      -- putanja do izdatog sertifikata (još nije generisan)
       );