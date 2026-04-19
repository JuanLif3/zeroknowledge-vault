package com.cybersec.zeroknowledge_vault.security.domain.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "blacklisted_tokens")
public class BlacklistedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, length = 512, nullable = false)
    private String token;

    // Guardamos cuándo expira para que luego podamos limpiar esta tabla y no crezca infinitamente
    @Column(nullable = false)
    private Date expiresAt;
}