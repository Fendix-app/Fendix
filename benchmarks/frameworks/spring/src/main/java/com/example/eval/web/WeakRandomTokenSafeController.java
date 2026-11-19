package com.example.eval.web;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WeakRandomTokenSafeController {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final JdbcTemplate jdbcTemplate;

    public WeakRandomTokenSafeController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/weak-random-token/safe")
    public ResponseEntity<Map<String, String>> requestPasswordReset(@RequestParam String email) {
        String token = new BigInteger(130, SECURE_RANDOM).toString(32); // EVAL-SAFE
        jdbcTemplate.update("INSERT INTO password_resets (email, token) VALUES (?, ?)", email, token);
        return ResponseEntity.accepted().body(Map.of("status", "reset email queued"));
    }
}
