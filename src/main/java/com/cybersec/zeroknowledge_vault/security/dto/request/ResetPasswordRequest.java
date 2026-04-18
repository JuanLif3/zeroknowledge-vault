package com.cybersec.zeroknowledge_vault.security.dto.request;
import lombok.Data;

@Data
public class ResetPasswordRequest {
    private String email;
    private String newAuthHash;          // El Hash de la nueva contraseña
    private String newEncryptedMasterKey; // La caja fuerte cerrada con la nueva contraseña
}