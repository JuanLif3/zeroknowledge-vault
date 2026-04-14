package com.cybersec.zeroknowledge_vault.vault.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record VaultItemRequest(
        @NotBlank(message = "El título cifrado no puede estar vacío")
        String encryptedTitle,

        @NotBlank(message = "El usuario cifrado no puede estar vacío")
        String encryptedUsername,

        @NotBlank(message = "La contraseña cifrada no puede estar vacía")
        String encryptedPassword,

        @NotNull(message = "Debe especificar si es un honeytoken")
        Boolean isHoneytoken
) {
}
