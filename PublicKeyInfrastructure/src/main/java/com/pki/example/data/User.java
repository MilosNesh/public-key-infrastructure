package com.pki.example.data;

import com.pki.example.dto.UserDTO;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@Entity
@Table(name="users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "name")
    private String name;

    @Column(name = "surname")
    private String surname;


    @Column(name = "password")
    private String password;

    @Column(name = "organization")
    private String organization;

    public User() {}

    public User(String email, String name, String surname, String password, String organization) {
        this.email = email;
        this.name = name;
        this.surname = surname;
        this.password = password;
        this.organization = organization;
    }
    public User(UserDTO userDTO) {
        this.email = userDTO.getEmail();
        this.name = userDTO.getName();
        this.surname = userDTO.getSurname();
        this.password = userDTO.getPassword();
        this.organization = userDTO.getOrganization();
    }

    public boolean isValid() {
        String emailRegex = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";
        if(!email.matches(emailRegex))
            return false;
        if(name.isEmpty() || surname.isEmpty() || password.isEmpty() || organization.isEmpty())
            return false;
        return true;
    }
}
