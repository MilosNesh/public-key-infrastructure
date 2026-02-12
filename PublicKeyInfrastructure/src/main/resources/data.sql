INSERT INTO ROLE (name) VALUES ('ROLE_USER');
INSERT INTO ROLE (name) VALUES ('ROLE_CAUSER');
INSERT INTO ROLE (name) VALUES ('ROLE_ADMIN');

INSERT INTO users ( activation_token, email, name, organization, password, surname, must_change_password)
VALUES ( null, 'petar@gmail.com', 'Petar', 'firma', '$2a$12$ZD1s6.mHRajrbwmoUJF3JuXH8vTYW1Yzm/KlM8ygM45jtV7FAA1wy', 'Petrovic', false);

INSERT INTO users ( activation_token, email, name, organization, password, surname, must_change_password)
VALUES ( null, 'marko@gmail.com', 'Marko', 'firma', '$2a$12$ZD1s6.mHRajrbwmoUJF3JuXH8vTYW1Yzm/KlM8ygM45jtV7FAA1wy', 'Petrovic', false);

INSERT INTO users ( activation_token, email, name, organization, password, surname, must_change_password)
VALUES ( null, 'mika@gmail.com', 'Mika', 'firma', '$2a$12$ZD1s6.mHRajrbwmoUJF3JuXH8vTYW1Yzm/KlM8ygM45jtV7FAA1wy', 'Mikic', false);

INSERT INTO public.user_role(
    user_id, role_id)
VALUES (1, 1);

INSERT INTO public.user_role(
    user_id, role_id)
VALUES (2, 2);

INSERT INTO public.user_role(
    user_id, role_id)
VALUES (3, 3);
