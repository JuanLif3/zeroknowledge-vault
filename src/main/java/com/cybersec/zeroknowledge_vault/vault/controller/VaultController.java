package com.cybersec.zeroknowledge_vault.vault.controller;

import com.cybersec.zeroknowledge_vault.vault.domain.model.IntrusionLog;
import com.cybersec.zeroknowledge_vault.vault.dto.request.VaultItemRequest;
import com.cybersec.zeroknowledge_vault.vault.dto.response.VaultItemResponse;
import com.cybersec.zeroknowledge_vault.vault.service.VaultService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/vault")
@RequiredArgsConstructor
public class VaultController {

    private final VaultService vaultService;

    // * POST: Guardar una nueva credencial
    @PostMapping
    public ResponseEntity<VaultItemResponse> saveVaultItem(
            @Valid @RequestBody VaultItemRequest request,
            Authentication authentication // * Spring Security nos da esto gracias a nuestro Filtro JWT
    ) {
        String userEmail = authentication.getName();
        return ResponseEntity.ok(vaultService.saveItem(request, userEmail));
    }

    // * GET: Obtener todas mis credenciales
    @GetMapping
    public ResponseEntity<List<VaultItemResponse>> getMyVault(Authentication authentication) {
        String userEmail = authentication.getName();
        return ResponseEntity.ok(vaultService.getUserVault(userEmail));
    }

    // * Leer las alertas del radar
    @GetMapping("/intrusions")
    public ResponseEntity<List<IntrusionLog>> getMyIntrusions(Authentication authentication) {
        return ResponseEntity.ok(vaultService.getUserIntrusions(authentication.getName()));
    }

    // * PUT: Editar una credencial existente
    @PutMapping("/{id}")
    public ResponseEntity<VaultItemResponse> updateVaultItem(
            @PathVariable UUID id,
            @Valid @RequestBody VaultItemRequest request,
            Authentication authentication
    ) {
        String userEmail = authentication.getName();
        return ResponseEntity.ok(vaultService.updateItem(id, request, userEmail));
    }

    // * DELETE: Eliminar una credencial
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteVaultItem(
            @PathVariable UUID id,
            Authentication authentication
    ) {
        String userEmail = authentication.getName();
        vaultService.deleteItem(id, userEmail);
        return ResponseEntity.noContent().build();
    }
}