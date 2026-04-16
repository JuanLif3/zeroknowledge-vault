package com.cybersec.zeroknowledge_vault.vault.dto.response;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SharedSecretResponse {
    private String id;
    private String encryptedMessage;
}