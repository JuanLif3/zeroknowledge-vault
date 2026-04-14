package com.cybersec.zeroknowledge_vault.security.Controller;

import com.cybersec.zeroknowledge_vault.security.dto.request.LoginRequest;
import com.cybersec.zeroknowledge_vault.security.dto.request.RegisterRequest;
import com.cybersec.zeroknowledge_vault.security.dto.response.AuthResponse;
import com.cybersec.zeroknowledge_vault.security.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
// Esto permite que nuestro futuro frontend en React (localhost:5173) pueda conectarse sin errores de CORS
@CrossOrigin(origins = "*")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
