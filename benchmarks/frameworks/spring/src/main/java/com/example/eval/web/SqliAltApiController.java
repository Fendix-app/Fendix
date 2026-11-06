package com.example.eval.web;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;

import javax.sql.DataSource;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SqliAltApiController {

    private final DataSource dataSource;

    public SqliAltApiController(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @GetMapping("/sqli/alt-api")
    public ResponseEntity<Map<String, Object>> findUser(@RequestParam String name) throws SQLException {
        try (Connection connection = dataSource.getConnection();
             Statement statement = connection.createStatement();
             ResultSet rs = statement.executeQuery("SELECT id, name, email FROM users WHERE name = '" + name + "'")) { // EVAL-SINK
            if (!rs.next()) {
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(Map.of(
                    "id", rs.getLong("id"),
                    "name", rs.getString("name"),
                    "email", rs.getString("email")));
        }
    }
}
