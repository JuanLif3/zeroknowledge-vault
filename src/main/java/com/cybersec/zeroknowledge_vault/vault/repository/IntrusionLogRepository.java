package com.cybersec.zeroknowledge_vault.vault.repository;

import com.cybersec.zeroknowledge_vault.vault.domain.model.IntrusionLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IntrusionLogRepository extends JpaRepository<IntrusionLog, Long> {
    // Obtener los ataques ordenados por el más reciente
    List<IntrusionLog> findByUserIdOrderByAttemptedAtDesc(Long userId);
}