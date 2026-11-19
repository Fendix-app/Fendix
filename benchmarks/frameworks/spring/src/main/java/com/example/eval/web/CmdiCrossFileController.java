package com.example.eval.web;

import java.io.IOException;
import java.util.Map;

import com.example.eval.service.NetworkDiagnosticsService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CmdiCrossFileController {

    private final NetworkDiagnosticsService networkDiagnosticsService;

    public CmdiCrossFileController(NetworkDiagnosticsService networkDiagnosticsService) {
        this.networkDiagnosticsService = networkDiagnosticsService;
    }

    @GetMapping("/cmdi/cross-file")
    public Map<String, String> ping(@RequestParam String host) throws IOException, InterruptedException {
        return Map.of("output", networkDiagnosticsService.ping(host));
    }
}
