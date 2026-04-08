package com.cybersec.zeroknowledge_vault.security.domain.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Data
public class User {

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
}
