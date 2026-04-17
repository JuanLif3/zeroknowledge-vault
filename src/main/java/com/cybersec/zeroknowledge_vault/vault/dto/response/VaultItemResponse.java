package com.cybersec.zeroknowledge_vault.vault.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class VaultItemResponse {
    private UUID id;
    private String encryptedTitle;
    private String encryptedPayload;
    private String itemType;
    private boolean isHoneytoken;
    private String trapToken;
    private LocalDateTime createdAt;
}