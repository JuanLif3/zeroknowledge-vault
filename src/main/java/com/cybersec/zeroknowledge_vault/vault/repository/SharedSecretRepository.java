package com.cybersec.zeroknowledge_vault.vault.repository;

import com.cybersec.zeroknowledge_vault.vault.domain.model.SharedSecret;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SharedSecretRepository extends JpaRepository<SharedSecret, String> {
}