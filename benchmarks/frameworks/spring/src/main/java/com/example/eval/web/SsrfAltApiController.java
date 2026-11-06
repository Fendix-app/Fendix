package com.example.eval.web;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SsrfAltApiController {

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @GetMapping("/ssrf/alt-api")
    public ResponseEntity<Map<String, Object>> fetch(@RequestParam String url) throws IOException, InterruptedException {
        HttpResponse<String> upstream = httpClient.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString()); // EVAL-SINK
        return ResponseEntity.ok(Map.of("status", upstream.statusCode(), "body", upstream.body()));
    }
}
