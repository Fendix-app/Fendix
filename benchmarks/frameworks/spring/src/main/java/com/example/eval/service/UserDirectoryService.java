package com.example.eval.service;

import java.util.List;
import java.util.Map;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class UserDirectoryService {

    private final JdbcTemplate jdbcTemplate;

    public UserDirectoryService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public List<Map<String, Object>> findByName(String name) {
        return jdbcTemplate.queryForList("SELECT id, name, email FROM users WHERE name = '" + name + "'"); // EVAL-SINK
    }
}
