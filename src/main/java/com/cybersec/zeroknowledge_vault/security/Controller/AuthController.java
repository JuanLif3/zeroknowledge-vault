package com.cybersec.zeroknowledge_vault.security.Controller;

import com.cybersec.zeroknowledge_vault.security.dto.request.LoginRequest;
import com.cybersec.zeroknowledge_vault.security.dto.request.RegisterRequest;
import com.cybersec.zeroknowledge_vault.security.dto.response.AuthResponse;
import com.cybersec.zeroknowledge_vault.security.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Value;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @Value("${app.security.cookie.secure:false}")
    private boolean isCookieSecure;

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

    // * Método privado CORREGIDO para generar la cookie blindada
    private void injectJwtCookie(HttpServletResponse response, String token) {
        ResponseCookie cookie = ResponseCookie.from("jwt", token) // Usamos la variable 'token' que llega por parámetro
                .httpOnly(true)
                .secure(isCookieSecure) // Usa la variable de entorno
                .path("/")
                .maxAge(24 * 60 * 60) // 1 día
                .sameSite("Strict") // <-- EL ESCUDO ANTI-CSRF
                .build();

        // Inyectamos la cabecera directamente en el response
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        ResponseCookie cookie = ResponseCookie.from("jwt", "")
                .httpOnly(true)
                .secure(isCookieSecure)
                .path("/")
                .maxAge(0) // <-- Autodestrucción instantánea
                .sameSite("Strict")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body("Sesión cerrada exitosamente");
    }

    // ==========================================
    // ENDPOINTS DE CONFIGURACIÓN 2FA
    // ==========================================

    // * Pedir el Código QR (El usuario debe estar logueado en la bóveda)
    @GetMapping("/2fa/setup")
    public ResponseEntity<Map<String, String>> setup2FA(Authentication authentication) {
        // Extraemos quién es el usuario directamente de su Cookie segura
        String email = authentication.getName();
        String qrCodeBase64 = authService.setup2FA(email);

        Map<String, String> response = new HashMap<>();
        response.put("qrCode", qrCodeBase64);
        return ResponseEntity.ok(response);
    }

    // * Enviar el primer número de 6 dígitos para activarlo
    @PostMapping("/2fa/enable")
    public ResponseEntity<Map<String, String>> enable2FA(
            @RequestBody Map<String, String> request,
            Authentication authentication) {

        String email = authentication.getName();
        String code = request.get("code"); // Obtenemos el número que tecleó en React

        authService.verifyAndEnable2FA(email, code);

        Map<String, String> response = new HashMap<>();
        response.put("message", "2FA activado con éxito");
        return ResponseEntity.ok(response);
    }
}