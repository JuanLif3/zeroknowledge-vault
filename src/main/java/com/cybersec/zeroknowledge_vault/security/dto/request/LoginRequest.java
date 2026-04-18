package com.cybersec.zeroknowledge_vault.security.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {
        @NotBlank(message = "El email es obligatorio")
        private String email;

        @NotBlank(message = "El Hash de la contraseña es obligatorio")
        private String authHash;

        // NUEVO: Campo opcional. Si viene vacío, sabemos que es su primer intento de login.
        private String twoFactorCode;
}