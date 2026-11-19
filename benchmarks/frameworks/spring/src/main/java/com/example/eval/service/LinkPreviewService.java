package com.example.eval.service;

import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class LinkPreviewService {

    private final RestTemplate restTemplate;

    public LinkPreviewService(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }

    public ResponseEntity<String> fetch(String url) {
        return restTemplate.getForEntity(url, String.class); // EVAL-SINK
    }
}
