package com.example.eval.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WeakPasswordHashDirectController {

    private final JdbcTemplate jdbcTemplate;

    public WeakPasswordHashDirectController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/weak-password-hash/direct")
    public ResponseEntity<Map<String, String>> register(@RequestParam String username, @RequestParam String password)
            throws NoSuchAlgorithmException {
        String passwordHash = HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(password.getBytes(StandardCharsets.UTF_8))); // EVAL-SINK
        jdbcTemplate.update("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, passwordHash);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("status", "registered"));
    }
}
