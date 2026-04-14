package com.cybersec.zeroknowledge_vault.security.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "El email es obligatorio")
        @Email
        String email,

        @NotBlank(message = "La contraseña es obligatoria")
        String password
) {
}
