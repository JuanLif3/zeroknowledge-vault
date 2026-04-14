package com.cybersec.zeroknowledge_vault.security.dto.response;

public record AuthResponse(
        String token,
        String message
) {
}
