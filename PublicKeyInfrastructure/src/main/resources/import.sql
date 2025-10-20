INSERT INTO ROLE (name) VALUES ('ROLE_USER');
INSERT INTO ROLE (name) VALUES ('ROLE_CAUSER');
INSERT INTO ROLE (name) VALUES ('ROLE_ADMIN');

INSERT INTO users(
    id, activation_token, email, name, organization, password, surname)
VALUES (1, 'abc123', 'shone@gmail.com', 'nenad', 'ftn', '123456', 'dubovac');

INSERT INTO csr_requests (user_id, certificate_id, csr_path, status, certificate_path)
VALUES (
           1,                                        -- user_id
           10,                                       -- certificate_id (npr. ID šablona ili CA sertifikata)
           'src/main/resources/csr/user_request.csr', -- putanja do CSR fajla
           'pending',                                -- trenutni status
           NULL                                      -- putanja do izdatog sertifikata (još nije generisan)
       );