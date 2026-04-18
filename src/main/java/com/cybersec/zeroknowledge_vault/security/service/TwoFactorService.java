package com.cybersec.zeroknowledge_vault.security.service;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import org.springframework.stereotype.Service;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Service
public class TwoFactorService {

    // * Generador del Secreto (La "semilla")
    public String generateNewSecret() {
        SecretGenerator generator = new DefaultSecretGenerator();
        return generator.generate();
    }

    // * Generador del Código QR en Base64 para mandarlo a React
    public String generateQrCodeImageUri(String secret, String email) {
        QrData data = new QrData.Builder()
                .label(email)
                .secret(secret)
                .issuer("Zero-Knowledge Vault") // Esto aparecerá en la app de Google Authenticator
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30) // El código cambia cada 30 segundos
                .build();

        QrGenerator generator = new ZxingPngQrGenerator();
        try {
            byte[] imageData = generator.generate(data);
            String mimeType = generator.getImageMimeType();
            return getDataUriForImage(imageData, mimeType);
        } catch (QrGenerationException e) {
            throw new RuntimeException("Error generando el Código QR");
        }
    }

    // * El Validador: Revisa si el número que puso el usuario coincide con la hora
    public boolean isOtpValid(String secret, String code) {
        TimeProvider timeProvider = new SystemTimeProvider();
        DefaultCodeGenerator codeGenerator = new DefaultCodeGenerator();
        // Permitimos una pequeña discrepancia de tiempo (por si el celular está un poco desfasado)
        CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

        return verifier.isValidCode(secret, code);
    }
}