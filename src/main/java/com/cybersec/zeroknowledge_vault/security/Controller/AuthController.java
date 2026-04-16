package com.cybersec.zeroknowledge_vault.security.Controller;

import com.cybersec.zeroknowledge_vault.security.dto.request.LoginRequest;
import com.cybersec.zeroknowledge_vault.security.dto.request.RegisterRequest;
import com.cybersec.zeroknowledge_vault.security.dto.response.AuthResponse;
import com.cybersec.zeroknowledge_vault.security.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletResponse response // Necesario para inyectar la cookie
    ) {
        AuthResponse authResponse = authService.register(request);
        injectJwtCookie(response, authResponse.getToken());

        return ResponseEntity.ok(AuthResponse.builder().token("JWT protegido en Cookie HttpOnly").build());
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response
    ) {
        AuthResponse authResponse = authService.login(request);
        injectJwtCookie(response, authResponse.getToken());

        return ResponseEntity.ok(AuthResponse.builder().token("JWT protegido en Cookie HttpOnly").build());
    }

    // * Método privado para generar la cookie blindada
    private void injectJwtCookie(HttpServletResponse response, String token) {
        Cookie cookie = new Cookie("jwt", token);
        cookie.setHttpOnly(true); // PROHÍBE que JavaScript (o hackers) lo lean
        cookie.setSecure(false); // en 'true' cuando se suba a producción con HTTPS
        cookie.setPath("/");
        cookie.setMaxAge(24 * 60 * 60); // Expira en 1 día
        response.addCookie(cookie);
    }
}