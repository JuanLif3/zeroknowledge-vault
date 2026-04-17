package com.cybersec.zeroknowledge_vault.vault.domain.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "intrusion_logs")
public class IntrusionLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private UUID vaultItemId; // El ID del señuelo que fue atacado

    @Column(nullable = false)
    private Long userId; // El dueño de la bóveda (Yo)

    private String ipAddress; // Desde dónde nos atacan

    private LocalDateTime attemptedAt;

    @PrePersist
    protected void onCreate() {
        attemptedAt = LocalDateTime.now();
    }
}