package com.cybersec.zeroknowledge_vault.security.service;

import com.cybersec.zeroknowledge_vault.security.domain.model.User;
import com.cybersec.zeroknowledge_vault.security.dto.request.LoginRequest;
import com.cybersec.zeroknowledge_vault.security.dto.request.RegisterRequest;
import com.cybersec.zeroknowledge_vault.security.dto.request.ResetPasswordRequest;
import com.cybersec.zeroknowledge_vault.security.dto.response.AuthResponse;
import com.cybersec.zeroknowledge_vault.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.SimpleMailMessage;
import java.security.SecureRandom;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TwoFactorService twoFactorService;
    private final JavaMailSender mailSender;

    public AuthResponse register(RegisterRequest request) {
        // * Verificamos si el correo existe (Usando getEmail)
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("El correo ya esta registrado");
        }

        // * Creamos al usuario
        User user = new User();
        user.setEmail(request.getEmail()); // Usando getEmail
        user.setLoginPasswordHash(passwordEncoder.encode(request.getAuthHash())); // Usando getPassword
        user.setSalt(request.getSalt());
        user.setEncryptedMasterKey(request.getEncryptedMasterKey());
        user.setRecoveryMasterKey(request.getRecoveryMasterKey());

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
        // Buscamos al usuario
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Credenciales incorrectas"));

        // VERIFICACIÓN DE BLOQUEO (Anti-Brute Force)
        if (!user.isAccountNonLocked()) {
            throw new RuntimeException("Cuenta bloqueada por múltiples intentos fallidos. Por seguridad, intente nuevamente en 15 minutos.");
        }

        try {
            // Intentamos autenticar con Spring Security (Verifica el Hash)
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getAuthHash()
                    )
            );

            // SI LLEGA AQUÍ, LA CLAVE ES CORRECTA
            // Delegamos el reinicio de fallos directamente a la BD de forma segura
            userRepository.resetFailedLogins(request.getEmail());

        } catch (Exception e) {
            // SI LLEGA AQUÍ, SE EQUIVOCÓ DE CONTRASEÑA

            // 1. Sumamos el fallo directamente en SQL para evitar Condición de Carrera
            userRepository.incrementFailedLogins(request.getEmail());

            // 2. Volvemos a leer al usuario para ver en qué número quedó exactamente
            User updatedUser = userRepository.findByEmail(request.getEmail()).get();
            int currentAttempts = updatedUser.getFailedLoginAttempts();

            if (currentAttempts >= 5) {
                // ¡PUM! Bloqueado por 15 minutos
                updatedUser.setAccountLockedUntil(LocalDateTime.now().plusMinutes(15));
                userRepository.save(updatedUser);
                throw new RuntimeException("Has superado el límite de intentos (5). Cuenta bloqueada temporalmente por 15 minutos.");
            }

            throw new RuntimeException("Credenciales incorrectas. Te quedan " + (5 - currentAttempts) + " intentos antes del bloqueo de seguridad.");
        }

        // ADUANA DE 2FA
        if (user.isTwoFactorEnabled()) {
            // Si el frontend no envió el código de 6 dígitos, le decimos: "Espera, falta el 2FA"
            if (request.getTwoFactorCode() == null || request.getTwoFactorCode().isEmpty()) {
                return AuthResponse.builder()
                        .token(null) // No le damos el token todavía
                        .requires2FA(true) // Le avisamos a React que levante la pantalla del código
                        .build();
            } else {
                // Si el frontend sí envió el código, la librería matemática lo valida
                boolean isCodeValid = twoFactorService.isOtpValid(user.getTwoFactorSecret(), request.getTwoFactorCode());
                if (!isCodeValid) {
                    throw new RuntimeException("Código 2FA inválido o expirado");
                }
            }
        }
        // ==========================================

        // * Generamos el token solo si todo fue perfecto (Clave correcta + 2FA correcto o apagado)
        String jwtToken = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(jwtToken)
                .requires2FA(false)
                .encryptedMasterKey(user.getEncryptedMasterKey())
                .build();
    }

    // ==========================================
    // MÉTODOS PARA 2FA (Google Authenticator)
    // ==========================================

    // Iniciar la configuración: Crea el secreto y devuelve la imagen del QR
    public String setup2FA(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (user.isTwoFactorEnabled()) {
            throw new RuntimeException("El 2FA ya está configurado y activo en esta cuenta.");
        }

        // Generamos un secreto nuevo y lo guardamos temporalmente (aún NO activamos el 2FA)
        String secret = twoFactorService.generateNewSecret();
        user.setTwoFactorSecret(secret);
        userRepository.save(user);

        // Devolvemos la imagen del código QR lista para mostrar en React
        return twoFactorService.generateQrCodeImageUri(secret, user.getEmail());
    }

    // Confirmar y Activar el 2FA definitivamente
    public void verifyAndEnable2FA(String email, String code) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (user.getTwoFactorSecret() == null) {
            throw new RuntimeException("Debes generar un QR primero");
        }

        // El motor matemático verifica si el código coincide con la hora actual
        boolean isValid = twoFactorService.isOtpValid(user.getTwoFactorSecret(), code);
        if (!isValid) {
            throw new RuntimeException("Código inválido o expirado. Intenta de nuevo.");
        }

        // Si el código es correcto, ¡encendemos el interruptor de seguridad!
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    public boolean is2FAEnabled(String email) {
        return userRepository.findByEmail(email)
                .map(User::isTwoFactorEnabled)
                .orElse(false);
    }

    // * MÉTODO PARA ENTREGAR EL SALT (Criptografía)
    public String getSalt(String email) {
        return userRepository.findByEmail(email)
                .map(User::getSalt)
                // Prevención de enumeración: Si un hacker pregunta por un correo que no existe,
                // le damos un Salt falso para que no sepa si el correo está registrado o no.
                .orElse("00000000-0000-0000-0000-000000000000");
    }

    // * Entregar la caja fuerte de emergencia
    public Map<String, String> getRecoveryData(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        Map<String, String> data = new HashMap<>();
        data.put("salt", user.getSalt());
        data.put("recoveryMasterKey", user.getRecoveryMasterKey());
        return data;
    }

    // * Guardar la nueva contraseña
    public void resetPassword(ResetPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Verificamos el código
        if (user.getResetOtp() == null || !user.getResetOtp().equals(request.getOtp())) {
            throw new RuntimeException("Código OTP incorrecto. Intento de secuestro bloqueado.");
        }
        if (user.getResetOtpExpiry() != null && user.getResetOtpExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("El código ha expirado. Solicita uno nuevo.");
        }

        user.setLoginPasswordHash(passwordEncoder.encode(request.getNewAuthHash()));
        user.setEncryptedMasterKey(request.getNewEncryptedMasterKey());
        user.setTwoFactorEnabled(false);

        // Limpiamos el código para que no se pueda reusar
        user.setResetOtp(null);
        user.setResetOtpExpiry(null);

        userRepository.save(user);
    }

    public void requestPasswordReset(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);

        // Si el correo no existe, nos detenemos en silencio sin lanzar error.
        // Para el atacante (y el frontend), parecerá que el correo se envió con éxito.
        if (userOpt.isEmpty()) {
            return;
        }

        User user = userOpt.get();

        try {
            // CRIPTOGRAFÍA FUERTE (SecureRandom):
            // Genera números utilizando la entropía del sistema operativo (impredecible)
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            String otp = String.format("%06d", secureRandom.nextInt(999999));

            user.setResetOtp(otp);
            user.setResetOtpExpiry(LocalDateTime.now().plusMinutes(15));
            userRepository.save(user);

            sendOtpEmail(email, otp);

        } catch (Exception e) {
            throw new RuntimeException("Error interno al generar código de seguridad");
        }
    }

    private void sendOtpEmail(String to, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("Código de Recuperación - ZK-Vault");
        message.setText("Has solicitado restablecer tu contraseña maestra.\n\n" +
                "Tu código de verificación es: " + otp + "\n\n" +
                "Este código expirará en 15 minutos. Si no solicitaste esto, ignora este correo.");

        mailSender.send(message);
    }
}