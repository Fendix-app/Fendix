package com.example.eval.web;

import java.math.BigInteger;
import java.util.Map;
import java.util.Random;

import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WeakRandomTokenDirectController {

    private final JdbcTemplate jdbcTemplate;

    public WeakRandomTokenDirectController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostMapping("/weak-random-token/direct")
    public ResponseEntity<Map<String, String>> requestPasswordReset(@RequestParam String email) {
        String token = new BigInteger(130, new Random()).toString(32); // EVAL-SINK
        jdbcTemplate.update("INSERT INTO password_resets (email, token) VALUES (?, ?)", email, token);
        return ResponseEntity.accepted().body(Map.of("status", "reset email queued"));
    }
}
