package com.cts;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.List;

@Component
public class JwtAuthFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String secret;

    private static final List<String> PUBLIC_URLS = List.of(
            "/api/users/register",
            "/api/users/login",
            "/api/users/forgot-password",
            "/api/users/reset-password",
            "/api/users/refresh"
    );

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        System.out.println("Gateway Filter - incoming path: " + path);

        // Skip public URLs
        if (PUBLIC_URLS.stream().anyMatch(path::startsWith)) {
            System.out.println("Gateway Filter - skipping public URL");
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest()
                .getHeaders().getFirst("Authorization");

        System.out.println("Gateway Filter - authHeader: " + authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            System.out.println("Gateway Filter - missing or invalid auth header");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String userId = claims.get("userId", Long.class).toString();
            String role = claims.get("role", String.class);
            String email = claims.getSubject();

            System.out.println("Gateway Filter - userId: " + userId);
            System.out.println("Gateway Filter - role: " + role);
            System.out.println("Gateway Filter - email: " + email);

            ServerHttpRequest mutatedRequest = exchange.getRequest()
                    .mutate()
                    .header("X-User-Id", userId)
                    .header("X-User-Role", role)
                    .header("X-User-Email", email)
                    .build();

            return chain.filter(exchange.mutate()
                    .request(mutatedRequest)
                    .build());

        } catch (Exception e) {
            System.out.println("Gateway Filter - Exception: " + e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        return -1;
    }
}