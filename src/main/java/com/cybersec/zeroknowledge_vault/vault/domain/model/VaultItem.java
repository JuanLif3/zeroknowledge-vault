package com.cybersec.zeroknowledge_vault.vault.domain.model;

import com.cybersec.zeroknowledge_vault.security.domain.model.User;
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
@Table(name = "vault_item")
public class VaultItem {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // A quién le pertenece esta credencial
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    // EJEMPLO DE DATOS QUE LLEGARÁN AQUÍ: "U2FsdGVkX19zX...a8f="
    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedTitle; // Ej: "Netflix" (pero cifrado)

    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedUsername; // Ej: "juan@mail.com" (pero cifrado)

    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedPassword; // Ej: "123456" (pero cifrado)

    @Column(nullable = false)
    private boolean isHoneytoken = false;

    // Para saber qué icono mostrar en React
    @Column(nullable = false)
    private String itemType;

    // Usamos TEXT porque el payload empaquetado puede ser muy largo
    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedPayload;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
