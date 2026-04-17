package com.cybersec.zeroknowledge_vault.vault.service;

import com.cybersec.zeroknowledge_vault.vault.domain.model.SharedSecret;
import com.cybersec.zeroknowledge_vault.vault.dto.request.SharedSecretRequest;
import com.cybersec.zeroknowledge_vault.vault.dto.response.SharedSecretResponse;
import com.cybersec.zeroknowledge_vault.vault.repository.SharedSecretRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.ZoneOffset;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class SharedSecretService {

    private final SharedSecretRepository repository;

    // * Crear el secreto
    public String createSecret(SharedSecretRequest request) {
        SharedSecret secret = SharedSecret.builder()
                .encryptedMessage(request.getEncryptedMessage())
                // USAMOS UTC PARA EVITAR CONFLICTOS CON EL SERVIDOR
                .expiresAt(LocalDateTime.now(ZoneOffset.UTC).plusMinutes(request.getMinutesToLive()))
                .holdToReveal(request.isHoldToReveal())
                .build();

        return repository.save(secret).getId();
    }

    // * Misión Suicida: Obtener y borrar
    @Transactional
    public SharedSecretResponse getAndDestroySecret(String id) {
        SharedSecret secret = repository.findById(id)
                .orElseThrow(() -> new RuntimeException("El secreto no existe o ya fue destruido"));

        // COMPARAMOS CONTRA UTC
        if (secret.getExpiresAt().isBefore(LocalDateTime.now(ZoneOffset.UTC))) {
            repository.delete(secret);
            repository.flush();
            throw new RuntimeException("El link ha caducado");
        }

        SharedSecretResponse response = SharedSecretResponse.builder()
                .id(secret.getId())
                .encryptedMessage(secret.getEncryptedMessage())
                .holdToReveal(secret.isHoldToReveal())
                .build();

        repository.deleteById(id);
        repository.flush();

        return response;
    }
}