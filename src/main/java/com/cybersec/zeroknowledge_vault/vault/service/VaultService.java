package com.cybersec.zeroknowledge_vault.vault.service;

import com.cybersec.zeroknowledge_vault.security.domain.model.User;
import com.cybersec.zeroknowledge_vault.security.repository.UserRepository;
import com.cybersec.zeroknowledge_vault.vault.domain.model.IntrusionLog;
import com.cybersec.zeroknowledge_vault.vault.domain.model.VaultItem;
import com.cybersec.zeroknowledge_vault.vault.dto.request.VaultItemRequest;
import com.cybersec.zeroknowledge_vault.vault.dto.response.VaultItemResponse;
import com.cybersec.zeroknowledge_vault.vault.repository.IntrusionLogRepository;
import com.cybersec.zeroknowledge_vault.vault.repository.VaultItemRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class VaultService {

    private final VaultItemRepository vaultItemRepository;
    private final UserRepository userRepository;
    private final IntrusionLogRepository intrusionLogRepository;

    // * CREAR UN NUEVO REGISTRO
    public VaultItemResponse saveItem(VaultItemRequest request, String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        VaultItem item = VaultItem.builder()
                .user(user)
                .encryptedTitle(request.getEncryptedTitle())
                .itemType(request.getItemType())
                .encryptedPayload(request.getEncryptedPayload())
                .isHoneytoken(request.isHoneytoken())
                // AHORA SÍ: Generamos el token de trampa al guardar
                .trapToken(request.isHoneytoken() ? UUID.randomUUID().toString() : null)
                .build();

        VaultItem savedItem = vaultItemRepository.save(item);
        return mapToResponse(savedItem);
    }

    // * OBTENER TODOS LOS REGISTROS
    public List<VaultItemResponse> getUserVault(String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        return vaultItemRepository.findAllByUserId(user.getId())
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    // * ACTUALIZAR UN REGISTRO EXISTENTE (EDITAR)
    public VaultItemResponse updateItem(Long id, VaultItemRequest request, String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        VaultItem item = vaultItemRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Ítem no encontrado"));

        if (!item.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("Acceso denegado: Este registro no te pertenece");
        }

        item.setEncryptedTitle(request.getEncryptedTitle());
        item.setItemType(request.getItemType());
        item.setEncryptedPayload(request.getEncryptedPayload());
        item.setHoneytoken(request.isHoneytoken());

        // LÓGICA DE LA TRAMPA AL EDITAR:
        // Si lo convertimos en Honeytoken y no tenía token, le creamos uno
        if (request.isHoneytoken() && item.getTrapToken() == null) {
            item.setTrapToken(UUID.randomUUID().toString());
        }
        // Si le quitamos el Honeytoken, le borramos el token de trampa
        else if (!request.isHoneytoken()) {
            item.setTrapToken(null);
        }

        VaultItem updatedItem = vaultItemRepository.save(item);
        return mapToResponse(updatedItem);
    }

    // * ELIMINAR UN REGISTRO
    public void deleteItem(Long id, String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        VaultItem item = vaultItemRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Ítem no encontrado"));

        if (!item.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("Acceso denegado: Este registro no te pertenece");
        }

        vaultItemRepository.delete(item);
    }

    // * REGISTRAR UN ATAQUE
    public void registerIntrusion(Long vaultItemId, String userEmail, String ipAddress) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        IntrusionLog log = IntrusionLog.builder()
                .vaultItemId(vaultItemId)
                .userId(user.getId())
                .ipAddress(ipAddress)
                .build();

        intrusionLogRepository.save(log);
    }

    // * OBTENER MIS ALERTAS
    public List<IntrusionLog> getUserIntrusions(String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        return intrusionLogRepository.findByUserIdOrderByAttemptedAtDesc(user.getId());
    }

    // * MAPPER (Transformar a DTO)
    private VaultItemResponse mapToResponse(VaultItem item) {
        return VaultItemResponse.builder()
                .id(item.getId())
                .encryptedTitle(item.getEncryptedTitle())
                .encryptedPayload(item.getEncryptedPayload())
                .itemType(item.getItemType())
                .isHoneytoken(item.isHoneytoken())
                .trapToken(item.getTrapToken()) // Mapeo del token hacia React
                .createdAt(item.getCreatedAt())
                .build();
    }
}