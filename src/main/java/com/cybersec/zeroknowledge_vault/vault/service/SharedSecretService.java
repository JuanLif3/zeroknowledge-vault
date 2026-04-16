package com.cybersec.zeroknowledge_vault.vault.service;

import com.cybersec.zeroknowledge_vault.vault.domain.model.SharedSecret;
import com.cybersec.zeroknowledge_vault.vault.dto.request.SharedSecretRequest;
import com.cybersec.zeroknowledge_vault.vault.dto.response.SharedSecretResponse;
import com.cybersec.zeroknowledge_vault.vault.repository.SharedSecretRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class SharedSecretService {

    private final SharedSecretRepository repository;

    // * Crear el secreto
    public String createSecret(SharedSecretRequest request) {
        SharedSecret secret = SharedSecret.builder()
                .encryptedMessage(request.getEncryptedMessage())
                .expiresAt(LocalDateTime.now().plusMinutes(request.getMinutesToLive()))
                .holdToReveal(request.isHoldToReveal()) // <-- NUEVO: Guardar el modo Snapchat en la BD
                .build();

        return repository.save(secret).getId();
    }

    // * Misión Suicida: Obtener y borrar
    @Transactional
    public SharedSecretResponse getAndDestroySecret(String id) {
        SharedSecret secret = repository.findById(id)
                .orElseThrow(() -> new RuntimeException("El secreto no existe o ya fue destruido"));

        // * Verificar si caducó por tiempo
        if (secret.getExpiresAt().isBefore(LocalDateTime.now())) {
            repository.delete(secret);
            throw new RuntimeException("El link ha caducado");
        }

        // * Preparamos la respuesta
        SharedSecretResponse response = SharedSecretResponse.builder()
                .id(secret.getId())
                .encryptedMessage(secret.getEncryptedMessage())
                .holdToReveal(secret.isHoldToReveal()) // <-- NUEVO: Enviar el modo Snapchat al Frontend
                .build();

        // ! Lo borramos de la DB justo después de leerlo
        repository.delete(secret);

        return response;
    }
}