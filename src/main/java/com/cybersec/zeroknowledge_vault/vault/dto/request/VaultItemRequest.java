package com.cybersec.zeroknowledge_vault.vault.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class VaultItemRequest {
        private String encryptedTitle;
        private String itemType;
        private String encryptedPayload;
        // Añadimos esto para que Java no se confunda al leer el JSON
        @JsonProperty("isHoneytoken")
        private boolean isHoneytoken;
}