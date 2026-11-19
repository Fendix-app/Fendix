package com.example.eval.web;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqliSafeController {

    private final JdbcTemplate jdbcTemplate;

    public SqliSafeController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/sqli/safe")
    public List<Map<String, Object>> searchUsers(@RequestParam String name) {
        return jdbcTemplate.queryForList("SELECT id, name, email FROM users WHERE name = ?", name); // EVAL-SAFE
    }
}
