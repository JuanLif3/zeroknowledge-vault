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

    // Aquí declaramos la variable como "userRepository"
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponse register(RegisterRequest request) {
        // * Verificamos si el correo existe (Usando getEmail)
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("El correo ya esta registrado");
        }

        // * Creamos al usuario
        User user = new User();
        user.setEmail(request.getEmail()); // Usando getEmail
        user.setLoginPasswordHash(passwordEncoder.encode(request.getPassword())); // Usando getPassword

        // * Guardamos en la DB
        userRepository.save(user);

        // * Generamos el Token
        String jwtToken = jwtService.generateToken(user);

        // * Retornamos el AuthResponse usando el Builder (Solo el token)
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthResponse login(LoginRequest request) {
        //  Buscamos al usuario (Usando userRepository y getEmail)
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Credenciales incorrectas"));

        //  VERIFICACIÓN DE BLOQUEO (Anti-Brute Force)
        if (!user.isAccountNonLocked()) {
            throw new RuntimeException("Cuenta bloqueada por múltiples intentos fallidos. Por seguridad, intente nuevamente en 15 minutos.");
        }

        try {
            // Intentamos autenticar con Spring Security
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            // SI LLEGA AQUÍ, EL LOGIN FUE EXITOSO: Reseteamos los fallos a 0
            user.setFailedLoginAttempts(0);
            user.setAccountLockedUntil(null);
            userRepository.save(user); // Usando userRepository

        } catch (Exception e) {
            // SI LLEGA AQUÍ, SE EQUIVOCÓ DE CONTRASEÑA: Sumamos un fallo
            int attempts = user.getFailedLoginAttempts() + 1;
            user.setFailedLoginAttempts(attempts);

            if (attempts >= 5) {
                // ¡PUM! Bloqueado por 15 minutos
                user.setAccountLockedUntil(LocalDateTime.now().plusMinutes(15));
                userRepository.save(user); // Usando userRepository
                throw new RuntimeException("Has superado el límite de intentos (5). Cuenta bloqueada temporalmente por 15 minutos.");
            }

            userRepository.save(user); // Usando userRepository
            throw new RuntimeException("Credenciales incorrectas. Te quedan " + (5 - attempts) + " intentos antes del bloqueo de seguridad.");
        }

        // Generamos el token solo si todo fue perfecto
        var jwtToken = jwtService.generateToken(user);
        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }
}