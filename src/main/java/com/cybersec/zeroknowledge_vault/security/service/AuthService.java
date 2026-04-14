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
        // * El AuthenticationManager de Spring comprueba internamente si la clave BCrypt coincide
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.email(),
                        request.password()
                )
        );

        // * Si llegamos a esta línea, las credenciales son correctas. Buscamos al usuario.
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(); // ! Nunca debería fallar porque ya autenticamos arriba

        // * Le damos un nuevo Token fresco
        String jwtToken = jwtService.generateToken(user);

        return new AuthResponse(jwtToken, "Login exitoso");
    }
}
