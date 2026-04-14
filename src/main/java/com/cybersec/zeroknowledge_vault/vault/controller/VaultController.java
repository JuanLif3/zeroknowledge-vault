package com.cybersec.zeroknowledge_vault.vault.controller;

import com.cybersec.zeroknowledge_vault.vault.dto.request.VaultItemRequest;
import com.cybersec.zeroknowledge_vault.vault.dto.response.VaultItemResponse;
import com.cybersec.zeroknowledge_vault.vault.service.VaultService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/vault")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class VaultController {

    private final VaultService vaultService;

    // * POST: Guardar una nueva credencial
    @PostMapping
    public ResponseEntity<VaultItemResponse> saveVaultItem(
            @Valid @RequestBody VaultItemRequest request,
            Authentication authentication // * Spring Security nos da esto gracias a nuestro Filtro JWT
    ) {
        // * Extraemos el email del usuario que hizo la petición
        String userEmail = authentication.getName();
        return ResponseEntity.ok(vaultService.saveItem(request, userEmail));
    }

    // * GET: Obtener todas mis credenciales
    @GetMapping
    public ResponseEntity<List<VaultItemResponse>> getMyVault(Authentication authentication) {
        String userEmail = authentication.getName();
        return ResponseEntity.ok(vaultService.getUserVault(userEmail));
    }
}
