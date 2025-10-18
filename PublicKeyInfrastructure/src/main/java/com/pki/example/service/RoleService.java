package com.pki.example.service;

import com.pki.example.data.Role;

import java.util.List;

public interface RoleService {
    Role findById(Long id);
    List<Role> findByName(String roleName);
}
