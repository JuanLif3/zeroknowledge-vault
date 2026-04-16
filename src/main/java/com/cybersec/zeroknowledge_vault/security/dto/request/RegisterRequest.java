package com.cybersec.zeroknowledge_vault.security.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

        @NotBlank(message = "El nombre es obligatorio")
        private String firstname;

        @NotBlank(message = "El apellido es obligatorio")
        private String lastname;

        @NotBlank(message = "El email es obligatorio")
        @Email(message = "Formato de email inválido")
        private String email;

        @NotBlank(message = "La contraseña es obligatoria")
        @Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=!*~_]).{12,}$",
                message = "La contraseña debe tener al menos 12 caracteres, una mayúscula, una minúscula, un número y un carácter especial.")
        private String password;
}