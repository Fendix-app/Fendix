package com.example.eval.web;

import java.util.Map;
import java.util.Objects;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class SsrfDirectController {

    private final RestTemplate restTemplate;

    public SsrfDirectController(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    @GetMapping("/ssrf/direct")
    public ResponseEntity<Map<String, Object>> fetch(@RequestParam String url) {
        ResponseEntity<String> upstream = restTemplate.getForEntity(url, String.class); // EVAL-SINK
        return ResponseEntity.ok(Map.of(
                "status", upstream.getStatusCode().value(),
                "body", Objects.requireNonNullElse(upstream.getBody(), "")));
    }
}
