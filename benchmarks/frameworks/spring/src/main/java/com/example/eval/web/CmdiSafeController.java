package com.example.eval.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CmdiSafeController {

    @GetMapping("/cmdi/safe")
    public Map<String, String> ping(@RequestParam String host) throws IOException, InterruptedException {
        Process process = new ProcessBuilder("ping", "-c", "1", host).redirectErrorStream(true).start(); // EVAL-SAFE
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        process.waitFor();
        return Map.of("output", output);
    }
}
