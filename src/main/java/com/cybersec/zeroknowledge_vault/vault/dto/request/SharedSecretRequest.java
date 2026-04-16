package com.cybersec.zeroknowledge_vault.vault.dto.request;

import lombok.Data;

@Data
public class SharedSecretRequest {
    private String encryptedMessage;
    private int minutesToLive; // Cuánto tiempo durará el link si nadie lo abre
}