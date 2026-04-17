package com.cybersec.zeroknowledge_vault.vault.controller;

import com.cybersec.zeroknowledge_vault.vault.domain.model.IntrusionLog;
import com.cybersec.zeroknowledge_vault.vault.domain.model.VaultItem;
import com.cybersec.zeroknowledge_vault.vault.repository.IntrusionLogRepository;
import com.cybersec.zeroknowledge_vault.vault.repository.VaultItemRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/trap")
@RequiredArgsConstructor
public class TrapController {

    private final VaultItemRepository vaultItemRepository;
    private final IntrusionLogRepository intrusionLogRepository;

    // ESTE ENDPOINT ES 100% PÚBLICO
    @GetMapping("/{token}")
    public ResponseEntity<?> triggerTrap(@PathVariable String token, HttpServletRequest request) {

        Optional<VaultItem> itemOpt = vaultItemRepository.findByTrapToken(token);

        if (itemOpt.isPresent()) {
            VaultItem item = itemOpt.get();

            // 1. Extraemos la IP real del atacante
            String attackerIp = request.getHeader("X-Forwarded-For");
            if (attackerIp == null) {
                attackerIp = request.getRemoteAddr();
            }

            // 2. Registramos la intrusión silenciosamente
            IntrusionLog log = IntrusionLog.builder()
                    .userId(item.getUser().getId())
                    .vaultItemId(item.getId())
                    .ipAddress(attackerIp)
                    .build();
            intrusionLogRepository.save(log);
        }

        // 3. ENGAÑAMOS AL HACKER
        // Le devolvemos un error de servidor clásico (500) o "Bad Gateway" (502).
        // Así el hacker pensará que la API de la empresa objetivo "está rota"
        // y no sospechará que acaba de caer en una trampa de ciberseguridad.
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("{\"error\": \"Internal Server Error\", \"status\": 500}");
    }
}