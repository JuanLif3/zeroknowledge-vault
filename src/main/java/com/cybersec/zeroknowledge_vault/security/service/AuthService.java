package com.cybersec.zeroknowledge_vault.security.service;

import com.cybersec.zeroknowledge_vault.security.domain.model.User;
import com.cybersec.zeroknowledge_vault.security.dto.request.LoginRequest;
import com.cybersec.zeroknowledge_vault.security.dto.request.RegisterRequest;
import com.cybersec.zeroknowledge_vault.security.dto.response.AuthResponse;
import com.cybersec.zeroknowledge_vault.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register (RegisterRequest request) {
        // * Verificamos si el correo existe para evitar errores
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new RuntimeException("El correo ya esta registrado");
        }

        // * Creamos al usuario, pero OJO: hasheamos la contraseña antes de guardarla
        User user = new User();
        user.setEmail(request.email());
        user.setLoginPasswordHash(passwordEncoder.encode(request.password()));

        // * Guardamos en la DB
        userRepository.save(user);

        // * Generamos su pase VIP (Token)
        String jwtToken = jwtService.generateToken(user);

        return new AuthResponse(jwtToken, "Usuario registrado exitosamente");
    }

    public AuthResponse login(LoginRequest request) {
        // 1. Buscamos al usuario (Si no existe, tiramos error genérico por seguridad)
        User user = repository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Credenciales incorrectas"));

        // 2. VERIFICACIÓN DE BLOQUEO (Anti-Brute Force)
        if (!user.isAccountNonLocked()) {
            throw new RuntimeException("Cuenta bloqueada por múltiples intentos fallidos. Por seguridad, intente nuevamente en 15 minutos.");
        }

        try {
            // 3. Intentamos autenticar con Spring Security
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            // 4. SI LLEGA AQUÍ, EL LOGIN FUE EXITOSO: Reseteamos los fallos a 0
            user.setFailedLoginAttempts(0);
            user.setAccountLockedUntil(null);
            repository.save(user);

        } catch (Exception e) {
            // 5. SI LLEGA AQUÍ, SE EQUIVOCÓ DE CONTRASEÑA: Sumamos un fallo
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            if (attempts >= 5) {
                // ¡PUM! Bloqueado por 15 minutos
                user.setAccountLockedUntil(LocalDateTime.now().plusMinutes(15));
                repository.save(user);
                throw new RuntimeException("Has superado el límite de intentos (5). Cuenta bloqueada temporalmente por 15 minutos.");
            }

            repository.save(user);
            throw new RuntimeException("Credenciales incorrectas. Te quedan " + (5 - attempts) + " intentos antes del bloqueo de seguridad.");
        }

        // Generamos el token solo si todo fue perfecto
        var jwtToken = jwtService.generateToken(user);
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }
}
