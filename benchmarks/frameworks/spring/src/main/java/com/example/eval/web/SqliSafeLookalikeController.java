package com.example.eval.web;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqliSafeLookalikeController {

    private static final String USERS_TABLE = "users";

    private final JdbcTemplate jdbcTemplate;

    public SqliSafeLookalikeController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/sqli/safe-lookalike")
    public List<Map<String, Object>> activeUsers() {
        return jdbcTemplate.queryForList("SELECT id, name, email FROM " + USERS_TABLE + " WHERE active = true ORDER BY name"); // EVAL-SAFE
    }
}
