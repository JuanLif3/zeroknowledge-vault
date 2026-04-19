package com.cybersec.zeroknowledge_vault.security.service;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    // No interceptar las rutas de Login y Registro
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        // El filtro SOLO se apaga (queda ciego) para estas dos rutas exactas.
        // Para todo lo demás (incluido el 2FA), el filtro debe leer la Cookie.
        return path.equals("/api/v1/auth/login") || path.equals("/api/v1/auth/register");
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String jwt = null;

        // 1. Buscamos la Cookie "jwt"
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals("jwt")) {
                    jwt = cookie.getValue();
                    break;
                }
            }
        }

        // Si no hay cookie, lo dejamos pasar
        if (jwt == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // 2. Extraer el usuario y validar
            final String userEmail = jwtService.extractUsername(jwt);

            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                if (jwtService.isTokenValid(jwt, userDetails) && !jwtService.isTokenBlacklisted(jwt)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            // Si la cookie es vieja/inválida o el usuario ya no existe,
            // atrapamos el error en silencio y seguimos. El usuario será tratado
            // como "No autenticado".
            System.out.println("Cookie JWT ignorada: " + e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}