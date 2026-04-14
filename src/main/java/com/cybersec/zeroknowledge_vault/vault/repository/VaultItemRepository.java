package com.cybersec.zeroknowledge_vault.vault.repository;

import com.cybersec.zeroknowledge_vault.vault.domain.model.VaultItem;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface VaultItemRepository extends JpaRepository<VaultItem, Long> {
    // * Magia de Spring Data: Busca todos los ítems filtrando por el ID del dueño
    List<VaultItem> findAllByUserId(Long userId);
}