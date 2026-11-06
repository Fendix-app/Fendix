package com.example.eval.web;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WeakPasswordHashSafeController {

    private final JdbcTemplate jdbcTemplate;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public WeakPasswordHashSafeController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/weak-password-hash/safe")
    public ResponseEntity<Map<String, String>> register(@RequestParam String username, @RequestParam String password) {
        String passwordHash = passwordEncoder.encode(password); // EVAL-SAFE
        jdbcTemplate.update("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, passwordHash);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("status", "registered"));
    }
}
