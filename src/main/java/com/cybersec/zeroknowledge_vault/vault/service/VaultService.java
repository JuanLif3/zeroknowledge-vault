package com.cybersec.zeroknowledge_vault.vault.service;

import com.cybersec.zeroknowledge_vault.security.domain.model.User;
import com.cybersec.zeroknowledge_vault.security.repository.UserRepository;
import com.cybersec.zeroknowledge_vault.vault.domain.model.VaultItem;
import com.cybersec.zeroknowledge_vault.vault.dto.request.VaultItemRequest;
import com.cybersec.zeroknowledge_vault.vault.dto.response.VaultItemResponse;
import com.cybersec.zeroknowledge_vault.vault.repository.VaultItemRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class VaultService {

    private final VaultItemRepository vaultItemRepository;
    private final UserRepository userRepository;

    public VaultItemResponse saveItem (VaultItemRequest request, String userEmail) {
        // * Buscamos al dueño de la boveda
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // * Creamos el ítem (recordemos que todo el texto ya viene cifrado desde React)
        VaultItem item = new VaultItem();
        item.setUser(user);
        item.setEncryptedTitle(request.encryptedTitle());
        item.setEncryptedUsername(request.encryptedUsername());
        item.setEncryptedPassword(request.encryptedPassword());
        item.setHoneytoken(request.isHoneytoken());

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
        return new VaultItemResponse(
                item.getId(),
                item.getEncryptedTitle(),
                item.getEncryptedUsername(),
                item.getEncryptedPassword(),
                item.isHoneytoken()
        );
    }
}