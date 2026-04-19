package com.cybersec.zeroknowledge_vault.security.repository;

import com.cybersec.zeroknowledge_vault.security.domain.model.User;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // Es vital buscar a los usuarios por su correo cuando intenten hacer login
    Optional<User> findByEmail(String email);

    // DELEGAMOS LA MATEMÁTICA A LA BASE DE DATOS (Anti Race-Condition)
    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.email = :email")
    void incrementFailedLogins(@Param("email") String email);

    @Modifying
    @Transactional
    @Query("UPDATE User u SET u.failedLoginAttempts = 0 WHERE u.email = :email")
    void resetFailedLogins(@Param("email") String email);
}
