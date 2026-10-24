package com.example.eval.web;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqliDirectController {

    private final JdbcTemplate jdbcTemplate;

    public SqliDirectController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/sqli/direct")
    public List<Map<String, Object>> searchUsers(@RequestParam String name) {
        return jdbcTemplate.queryForList("SELECT id, name, email FROM users WHERE name = '" + name + "'"); // EVAL-SINK
    }
}
