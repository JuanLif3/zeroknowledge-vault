package com.cybersec.zeroknowledge_vault.security.repository;

import com.cybersec.zeroknowledge_vault.security.domain.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // Es vital buscar a los usuarios por su correo cuando intenten hacer login
    Optional<User> findByEmail(String email);
}
