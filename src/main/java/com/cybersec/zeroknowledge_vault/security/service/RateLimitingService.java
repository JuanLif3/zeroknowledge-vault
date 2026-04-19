package com.cybersec.zeroknowledge_vault.security.service;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RateLimitingService {

    // Memoria caché para rastrear IPs
    private final Map<String, Bucket> loginBuckets = new ConcurrentHashMap<>();
    private final Map<String, Bucket> criticalBuckets = new ConcurrentHashMap<>();

    // LÍMITE DE LOGIN: 10 intentos máximo por minuto
    public Bucket resolveLoginBucket(String ip) {
        return loginBuckets.computeIfAbsent(ip, this::newLoginBucket);
    }

    // LÍMITE DE REGISTRO/RECUPERACIÓN: 3 intentos máximo por HORA
    public Bucket resolveCriticalBucket(String ip) {
        return criticalBuckets.computeIfAbsent(ip, this::newCriticalBucket);
    }

    private Bucket newLoginBucket(String ip) {
        Bandwidth limit = Bandwidth.classic(10, Refill.greedy(10, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    private Bucket newCriticalBucket(String ip) {
        // Operaciones críticas cuestan caro (crear cuentas, mandar emails)
        Bandwidth limit = Bandwidth.classic(3, Refill.intervally(3, Duration.ofHours(1)));
        return Bucket.builder().addLimit(limit).build();
    }
}