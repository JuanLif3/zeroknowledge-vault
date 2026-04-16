package com.cybersec.zeroknowledge_vault.vault.controller;

import com.cybersec.zeroknowledge_vault.vault.dto.request.SharedSecretRequest;
import com.cybersec.zeroknowledge_vault.vault.dto.response.SharedSecretResponse;
import com.cybersec.zeroknowledge_vault.vault.service.SharedSecretService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/shared-secrets")
@RequiredArgsConstructor
@CrossOrigin(origins = "*") // Permitimos que cualquiera acceda
public class SharedSecretController {

    private final SharedSecretService secretService;

    // Crear un secreto (Esto lo hace el usuario logueado)
    @PostMapping
    public ResponseEntity<String> createSecret(@RequestBody SharedSecretRequest request) {
        return ResponseEntity.ok(secretService.createSecret(request));
    }

    // Obtener un secreto (Esto lo hace el amigo que recibe el link)
    @GetMapping("/{id}")
    public ResponseEntity<SharedSecretResponse> getSecret(@PathVariable String id) {
        return ResponseEntity.ok(secretService.getAndDestroySecret(id));
    }
}