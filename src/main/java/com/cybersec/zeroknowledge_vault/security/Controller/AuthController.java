package com.cybersec.zeroknowledge_vault.security.Controller;

import com.cybersec.zeroknowledge_vault.security.dto.request.LoginRequest;
import com.cybersec.zeroknowledge_vault.security.dto.request.RegisterRequest;
import com.cybersec.zeroknowledge_vault.security.dto.request.ResetPasswordRequest;
import com.cybersec.zeroknowledge_vault.security.dto.response.AuthResponse;
import com.cybersec.zeroknowledge_vault.security.service.AuthService;
import com.cybersec.zeroknowledge_vault.security.service.RateLimitingService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RateLimitingService rateLimitingService;

    @Value("${app.security.cookie.secure:false}")
    private boolean isCookieSecure;

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletResponse response,
            HttpServletRequest httpRequest // <- Obtenemos la IP
    ) {
        // 🛡️ ADUANA DE RATE LIMITING: Máximo 3 registros por hora por IP
        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitingService.resolveCriticalBucket(ip).tryConsume(1)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "Límite de creación de cuentas alcanzado. Intenta en 1 hora."));
        }

        AuthResponse authResponse = authService.register(request);
        injectJwtCookie(response, authResponse.getToken());

        return ResponseEntity.ok(AuthResponse.builder().token("JWT protegido en Cookie HttpOnly").build());
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response,
            HttpServletRequest httpRequest // <- Obtenemos la IP
    ) {
        // 🛡️ ADUANA DE RATE LIMITING: Máximo 10 intentos de login por minuto por IP
        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitingService.resolveLoginBucket(ip).tryConsume(1)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "Demasiadas peticiones de acceso. Intenta en 1 minuto."));
        }

        // Ejecutamos la lógica de login (Que ahora incluye la parada del 2FA)
        AuthResponse authResponse = authService.login(request);

        // SOLO creamos la Cookie si la aduana del 2FA nos entregó un Token válido
        if (authResponse.getToken() != null && !authResponse.getToken().isEmpty()) {
            Cookie cookie = new Cookie("jwt", authResponse.getToken());
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(24 * 60 * 60); // 1 día
            // cookie.setSecure(true); // Descomentar en producción (HTTPS)

            response.addCookie(cookie);
        }

        // Devolvemos la respuesta a React (React leerá el requires2FA)
        return ResponseEntity.ok(authResponse);
    }

    // * Método privado CORREGIDO para generar la cookie blindada
    private void injectJwtCookie(HttpServletResponse response, String token) {
        ResponseCookie cookie = ResponseCookie.from("jwt", token)
                .httpOnly(true)
                .secure(isCookieSecure)
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

    @GetMapping("/2fa/setup")
    public ResponseEntity<Map<String, String>> setup2FA(Authentication authentication) {
        String email = authentication.getName();
        String qrCodeBase64 = authService.setup2FA(email);

        Map<String, String> response = new HashMap<>();
        response.put("qrCode", qrCodeBase64);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/2fa/enable")
    public ResponseEntity<Map<String, String>> enable2FA(
            @RequestBody Map<String, String> request,
            Authentication authentication) {

        String email = authentication.getName();
        String code = request.get("code");

        authService.verifyAndEnable2FA(email, code);

        Map<String, String> response = new HashMap<>();
        response.put("message", "2FA activado con éxito");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/2fa/status")
    public ResponseEntity<Map<String, Boolean>> check2FAStatus(Authentication authentication) {
        String email = authentication.getName();
        boolean isEnabled = authService.is2FAEnabled(email);

        Map<String, Boolean> response = new HashMap<>();
        response.put("isEnabled", isEnabled);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/salt/{email}")
    public ResponseEntity<Map<String, String>> getSalt(@PathVariable String email) {
        String salt = authService.getSalt(email);
        Map<String, String> response = new HashMap<>();
        response.put("salt", salt);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/recovery-data/{email}")
    public ResponseEntity<Map<String, String>> getRecoveryData(@PathVariable String email) {
        return ResponseEntity.ok(authService.getRecoveryData(email));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request);
        Map<String, String> response = new HashMap<>();
        response.put("message", "Contraseña restablecida con éxito");
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(
            @RequestBody Map<String, String> request,
            HttpServletRequest httpRequest // <- Obtenemos la IP
    ) {
        // ADUANA DE RATE LIMITING: Máximo 3 correos por hora por IP
        String ip = httpRequest.getRemoteAddr();
        if (!rateLimitingService.resolveCriticalBucket(ip).tryConsume(1)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("error", "Límite de correos superado. Intenta más tarde."));
        }

        authService.requestPasswordReset(request.get("email"));

        Map<String, String> response = new HashMap<>();
        response.put("message", "Si el correo existe, hemos enviado un código.");
        return ResponseEntity.ok(response);
    }
}