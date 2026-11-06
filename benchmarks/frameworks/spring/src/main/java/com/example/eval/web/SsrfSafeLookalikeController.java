package com.example.eval.web;

import java.util.Map;
import java.util.Objects;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class SsrfSafeLookalikeController {

    private static final String UPSTREAM_STATUS_URL = "https://status.example.com/api/v2/status.json";

    private final RestTemplate restTemplate;

    public SsrfSafeLookalikeController(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    @GetMapping("/ssrf/safe-lookalike")
    public ResponseEntity<Map<String, Object>> upstreamStatus() {
        ResponseEntity<String> upstream = restTemplate.getForEntity(UPSTREAM_STATUS_URL, String.class); // EVAL-SAFE
        return ResponseEntity.ok(Map.of(
                "status", upstream.getStatusCode().value(),
                "body", Objects.requireNonNullElse(upstream.getBody(), "")));
    }
}
