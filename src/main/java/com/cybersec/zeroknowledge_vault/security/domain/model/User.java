package com.cybersec.zeroknowledge_vault.security.domain.model;

import jakarta.persistence.*;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
@Data
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    // * Esta contraseña ES SOLO PARA INICIAR SESIÓN (Estará hasheada con BCrypt).
    // * NO es la contraseña que encriptará la bóveda, esa nunca llega aquí.
    @Column(nullable = false)
    private String loginPasswordHash;

    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    // * --- CAMPOS DE SEGURIDAD ANTI-HACKER ---
    @Column(name = "failed_login_attempts")
    private int failedLoginAttempts = 0;

    @Column(name = "account_locked_until")
    private LocalDateTime accountLockedUntil;

    // * --- METODOS OBLIATORIOS DE SPRING SECURITY ---
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(); // Todos tienen los mismos permisos en su propia bóveda
    }

    @Override
    public String getPassword() {
        return loginPasswordHash;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        if (accountLockedUntil == null) {
            return true;
        }
        // Si la fecha actual ya pasó la fecha de bloqueo, se desbloquea
        return LocalDateTime.now().isAfter(accountLockedUntil);
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }



}
