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
public class WeakPasswordHashIndirectController {

    private final JdbcTemplate jdbcTemplate;

    public WeakPasswordHashIndirectController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/weak-password-hash/indirect")
    public ResponseEntity<Map<String, String>> register(@RequestParam String username, @RequestParam String password)
            throws NoSuchAlgorithmException {
        jdbcTemplate.update("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, hashPassword(password));
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("status", "registered"));
    }

    private String hashPassword(String password) throws NoSuchAlgorithmException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(password.getBytes(StandardCharsets.UTF_8))); // EVAL-SINK
    }
}
