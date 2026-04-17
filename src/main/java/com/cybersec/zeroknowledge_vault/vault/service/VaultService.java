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

    public VaultItemResponse saveItem (VaultItemRequest request, String userEmail) {
        // * Buscamos al dueño de la boveda
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // * Creamos el ítem (recordemos que todo el texto ya viene cifrado desde React)
        VaultItem item = VaultItem.builder()
                .user(user)
                .encryptedTitle(request.getEncryptedTitle())
                .itemType(request.getItemType()) // Nuevo campo
                .encryptedPayload(request.getEncryptedPayload()) // Nuevo campo
                .isHoneytoken(request.isHoneytoken())
                .build();

        // * Guardamos en la base de datos
        VaultItem savedItem = vaultItemRepository.save(item);

        // * Devolvemos el DTO
        return mapToResponse(savedItem);
    }

    public List<VaultItemResponse> getUserVault (String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // * Extraemos SOLO los datos de este usuario y los transformamos en DTOs
        return vaultItemRepository.findAllByUserId(user.getId())
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    // * Método auxiliar para no repetir código
    private VaultItemResponse mapToResponse(VaultItem item) {
        return VaultItemResponse.builder()
                .id(item.getId())
                .encryptedTitle(item.getEncryptedTitle())
                .itemType(item.getItemType())
                .encryptedPayload(item.getEncryptedPayload()) 
                .isHoneytoken(item.isHoneytoken())
                .build();
    }

    // * Registrar un ataque
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

    // * Obtener mis alertas
    public List<IntrusionLog> getUserIntrusions(String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        return intrusionLogRepository.findByUserIdOrderByAttemptedAtDesc(user.getId());
    }

    // * Actualizar un registro existente (EDITAR)
    public VaultItemResponse updateItem(Long id, VaultItemRequest request, String userEmail) {
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        VaultItem item = vaultItemRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Ítem no encontrado"));

        // Verificamos que el ítem le pertenezca al usuario que lo quiere editar
        if (!item.getUser().getId().equals(user.getId())) {
            throw new RuntimeException("Acceso denegado: Este registro no te pertenece");
        }

        item.setEncryptedTitle(request.getEncryptedTitle());
        item.setItemType(request.getItemType());
        item.setEncryptedPayload(request.getEncryptedPayload());
        item.setHoneytoken(request.isHoneytoken());

        VaultItem updatedItem = vaultItemRepository.save(item);
        return mapToResponse(updatedItem);
    }

    // * Eliminar un registro (BORRAR)
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

    public VaultItemResponse createItem(VaultItemRequest request, User user) {
        VaultItem item = VaultItem.builder()
                .user(user)
                .encryptedTitle(request.getEncryptedTitle())
                .encryptedPayload(request.getEncryptedPayload())
                .itemType(request.getItemType())
                .isHoneytoken(request.isHoneytoken())
                // AÑADIMOS ESTO: Si es honeytoken, le damos un UUID aleatorio
                .trapToken(request.isHoneytoken() ? UUID.randomUUID().toString() : null)
                .build();

        VaultItem savedItem = vaultItemRepository.save(item);
        return mapToResponse(savedItem);
    }
}