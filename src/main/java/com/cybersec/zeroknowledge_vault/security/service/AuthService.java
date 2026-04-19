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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.springframework.beans.factory.annotation.Value;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TwoFactorService twoFactorService;
    private final JavaMailSender mailSender;

    // Llave secreta exclusiva para engañar a los atacantes
    @Value("${app.security.fake-salt-secret:SuperSecretoAntiEnumeracion2026}")
    private String fakeSaltSecret;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("El correo ya esta registrado");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setLoginPasswordHash(passwordEncoder.encode(request.getAuthHash()));
        user.setSalt(request.getSalt());
        user.setEncryptedMasterKey(request.getEncryptedMasterKey());
        user.setRecoveryMasterKey(request.getRecoveryMasterKey());

        userRepository.save(user);

        String jwtToken = jwtService.generateToken(user);

        return AuthResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Credenciales incorrectas"));

        if (!user.isAccountNonLocked()) {
            throw new RuntimeException("Cuenta bloqueada por múltiples intentos fallidos. Por seguridad, intente nuevamente en 15 minutos.");
        }

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getAuthHash()
                    )
            );

            userRepository.resetFailedLogins(request.getEmail());

        } catch (Exception e) {
            userRepository.incrementFailedLogins(request.getEmail());

            User updatedUser = userRepository.findByEmail(request.getEmail()).get();
            int currentAttempts = updatedUser.getFailedLoginAttempts();

            if (currentAttempts >= 5) {
                updatedUser.setAccountLockedUntil(LocalDateTime.now().plusMinutes(15));
                userRepository.save(updatedUser);
                throw new RuntimeException("Has superado el límite de intentos (5). Cuenta bloqueada temporalmente por 15 minutos.");
            }

            throw new RuntimeException("Credenciales incorrectas. Te quedan " + (5 - currentAttempts) + " intentos antes del bloqueo de seguridad.");
        }

        if (user.isTwoFactorEnabled()) {
            if (request.getTwoFactorCode() == null || request.getTwoFactorCode().isEmpty()) {
                return AuthResponse.builder()
                        .token(null)
                        .requires2FA(true)
                        .build();
            } else {
                boolean isCodeValid = twoFactorService.isOtpValid(user.getTwoFactorSecret(), request.getTwoFactorCode());
                if (!isCodeValid) {
                    throw new RuntimeException("Código 2FA inválido o expirado");
                }
            }
        }

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

    public String setup2FA(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (user.isTwoFactorEnabled()) {
            throw new RuntimeException("El 2FA ya está configurado y activo en esta cuenta.");
        }

        String secret = twoFactorService.generateNewSecret();
        user.setTwoFactorSecret(secret);
        userRepository.save(user);

        return twoFactorService.generateQrCodeImageUri(secret, user.getEmail());
    }

    public void verifyAndEnable2FA(String email, String code) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (user.getTwoFactorSecret() == null) {
            throw new RuntimeException("Debes generar un QR primero");
        }

        boolean isValid = twoFactorService.isOtpValid(user.getTwoFactorSecret(), code);
        if (!isValid) {
            throw new RuntimeException("Código inválido o expirado. Intenta de nuevo.");
        }

        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    public boolean is2FAEnabled(String email) {
        return userRepository.findByEmail(email)
                .map(User::isTwoFactorEnabled)
                .orElse(false);
    }

    // ==========================================
    // MÉTODO PARA ENTREGAR EL SALT (Criptografía)
    // ==========================================
    public String getSalt(String email) {
        return userRepository.findByEmail(email)
                .map(User::getSalt)
                // Prevención de enumeración: generamos un salt falso pero consistente (determinista)
                .orElseGet(() -> generateDeterministicFakeSalt(email));
    }

    // Nuevo método privado para fabricar el engaño
    private String generateDeterministicFakeSalt(String email) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            // Mezclamos el correo con nuestro secreto del servidor
            byte[] hash = digest.digest((email + fakeSaltSecret).getBytes(StandardCharsets.UTF_8));

            // Convertimos los bytes a formato Hexadecimal (como un Salt real)
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            // Devolvemos los primeros 32 caracteres (que es el tamaño típico de un Salt hexadecimal)
            return hexString.toString().substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            return "00000000000000000000000000000000"; // Fallback en caso de error crítico interno
        }
    }

    // ==========================================

    public Map<String, String> getRecoveryData(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        Map<String, String> data = new HashMap<>();
        data.put("salt", user.getSalt());
        data.put("recoveryMasterKey", user.getRecoveryMasterKey());
        return data;
    }

    public void resetPassword(ResetPasswordRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (user.getResetOtp() == null || !user.getResetOtp().equals(request.getOtp())) {
            throw new RuntimeException("Código OTP incorrecto. Intento de secuestro bloqueado.");
        }
        if (user.getResetOtpExpiry() != null && user.getResetOtpExpiry().isBefore(LocalDateTime.now())) {
            throw new RuntimeException("El código ha expirado. Solicita uno nuevo.");
        }

        user.setLoginPasswordHash(passwordEncoder.encode(request.getNewAuthHash()));
        user.setEncryptedMasterKey(request.getNewEncryptedMasterKey());
        user.setTwoFactorEnabled(false);

        user.setResetOtp(null);
        user.setResetOtpExpiry(null);

        userRepository.save(user);
    }

    public void requestPasswordReset(String email) {
        Optional<User> userOpt = userRepository.findByEmail(email);

        if (userOpt.isEmpty()) {
            return;
        }

        User user = userOpt.get();

        try {
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