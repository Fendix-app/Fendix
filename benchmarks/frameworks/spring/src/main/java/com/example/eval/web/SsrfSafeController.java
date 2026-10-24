package com.example.eval.web;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class SsrfSafeController {

    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com", "cdn.example.com");

    private final RestTemplate restTemplate;

    public SsrfSafeController(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    @GetMapping("/ssrf/safe")
    public ResponseEntity<Map<String, Object>> fetch(@RequestParam String url) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            return ResponseEntity.badRequest().build();
        }
        if (!"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
            return ResponseEntity.badRequest().build();
        }
        ResponseEntity<String> upstream = restTemplate.getForEntity(uri, String.class); // EVAL-SAFE
        return ResponseEntity.ok(Map.of(
                "status", upstream.getStatusCode().value(),
                "body", Objects.requireNonNullElse(upstream.getBody(), "")));
    }
}
