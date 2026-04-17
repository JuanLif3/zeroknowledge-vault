package com.cybersec.zeroknowledge_vault.vault.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class VaultItemResponse {
    private Long id;
    private String encryptedTitle;
    private String itemType;
    private String encryptedPayload;
    private boolean isHoneytoken;
    private String trapToken;
    private LocalDateTime createdAt;
}