package com.cybersec.zeroknowledge_vault.security.repository;

import com.cybersec.zeroknowledge_vault.security.domain.model.BlacklistedToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {
    boolean existsByToken(String token);
}