package com.example.eval.web;

import java.util.Map;
import java.util.Objects;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HardcodedSecretAltApiController {

    private static final String REPORTING_DB_URL = "jdbc:postgresql://db.internal:5432/app?user=app&password=__EVAL_DB_PASSWORD__"; // EVAL-SINK

    private final JdbcTemplate reportingJdbcTemplate = new JdbcTemplate(new DriverManagerDataSource(REPORTING_DB_URL));

    @GetMapping("/hardcoded-secret/alt-api")
    public Map<String, Long> orderCount() {
        Long orders = reportingJdbcTemplate.queryForObject("SELECT count(*) FROM orders", Long.class);
        return Map.of("orders", Objects.requireNonNullElse(orders, 0L));
    }
}
