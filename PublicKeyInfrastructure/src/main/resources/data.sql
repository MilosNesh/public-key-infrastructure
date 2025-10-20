INSERT INTO ROLE (name) VALUES ('ROLE_USER');
INSERT INTO ROLE (name) VALUES ('ROLE_CAUSER');
INSERT INTO ROLE (name) VALUES ('ROLE_ADMIN');

INSERT INTO users ( activation_token, email, name, organization, password, surname)
VALUES ( null, 'petar@gmail.com', 'Petar', 'firma', '$2a$12$ZD1s6.mHRajrbwmoUJF3JuXH8vTYW1Yzm/KlM8ygM45jtV7FAA1wy', 'Petrovic');

INSERT INTO users ( activation_token, email, name, organization, password, surname)
VALUES ( null, 'marko@gmail.com', 'Marko', 'firma', '$2a$12$ZD1s6.mHRajrbwmoUJF3JuXH8vTYW1Yzm/KlM8ygM45jtV7FAA1wy', 'Petrovic');

INSERT INTO public.user_role(
    user_id, role_id)
VALUES (1, 1);

INSERT INTO public.user_role(
    user_id, role_id)
VALUES (2, 2);

INSERT INTO csr_requests (user_id, certificate_id, csr_path, status, certificate_path)
VALUES (
           1,                                        -- user_id
           10,                                       -- certificate_id (npr. ID šablona ili CA sertifikata)
           'src/main/resources/csr/user_request.csr', -- putanja do CSR fajla
           'PENDING',                                -- trenutni status
           NULL                                      -- putanja do izdatog sertifikata (još nije generisan)
       );