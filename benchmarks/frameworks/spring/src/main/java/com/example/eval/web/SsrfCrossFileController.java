package com.example.eval.web;

import java.util.Map;
import java.util.Objects;

import com.example.eval.service.LinkPreviewService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SsrfCrossFileController {

    private final LinkPreviewService linkPreviewService;

    public SsrfCrossFileController(LinkPreviewService linkPreviewService) {
        this.linkPreviewService = linkPreviewService;
    }

    @GetMapping("/ssrf/cross-file")
    public ResponseEntity<Map<String, Object>> fetch(@RequestParam String url) {
        ResponseEntity<String> upstream = linkPreviewService.fetch(url);
        return ResponseEntity.ok(Map.of(
                "status", upstream.getStatusCode().value(),
                "body", Objects.requireNonNullElse(upstream.getBody(), "")));
    }
}
