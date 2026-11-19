package com.example.eval.web;

import java.util.List;
import java.util.Map;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class HardcodedSecretIndirectController {

    private static final Map<String, String> GITHUB_CONFIG = Map.of(
            "apiUrl", "https://api.github.com",
            "token", "__EVAL_GITHUB_TOKEN__"); // EVAL-SINK

    private final RestTemplate restTemplate;

    public HardcodedSecretIndirectController(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    @GetMapping("/hardcoded-secret/indirect")
    public ResponseEntity<String> listRepos() {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(fetchGitHubRepos());
    }

    private String fetchGitHubRepos() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, "Bearer " + GITHUB_CONFIG.get("token"));
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        ResponseEntity<String> response = restTemplate.exchange(
                GITHUB_CONFIG.get("apiUrl") + "/user/repos", HttpMethod.GET, new HttpEntity<>(headers), String.class);
        return response.getBody();
    }
}
