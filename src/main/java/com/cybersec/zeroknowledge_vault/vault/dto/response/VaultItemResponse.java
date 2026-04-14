package com.cybersec.zeroknowledge_vault.vault.dto.response;

public record VaultItemResponse(
        Long id,
        String encryptedTitle,
        String encryptedUsername,
        String encryptedPassword,
        boolean isHoneytoken
) {
}
