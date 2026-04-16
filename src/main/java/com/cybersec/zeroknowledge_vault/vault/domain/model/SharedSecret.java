package com.cybersec.zeroknowledge_vault.vault.domain.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "shared_secrets")
public class SharedSecret {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID) // Usamos UUID (texto aleatorio largo) en lugar de 1, 2, 3 para que no puedan adivinar el ID.
    private String id;

    // Solo guardamos el mensaje cifrado. Java jamás sabrá qué dice.
    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedMessage;

    // Fecha en la que caduca el link (Ej: 24 horas después)
    @Column(nullable = false)
    private LocalDateTime expiresAt;

    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    private boolean holdToReveal;
}