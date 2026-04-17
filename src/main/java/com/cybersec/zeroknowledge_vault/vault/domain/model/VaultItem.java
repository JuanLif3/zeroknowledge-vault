package com.cybersec.zeroknowledge_vault.vault.domain.model;

import com.cybersec.zeroknowledge_vault.security.domain.model.User;
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
@Table(name = "vault_item")
public class VaultItem {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedTitle;

    @Column(nullable = false)
    private boolean isHoneytoken = false;

    @Column(name = "trap_token", unique = true)
    private String trapToken;

    @Column(nullable = false)
    private String itemType;

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