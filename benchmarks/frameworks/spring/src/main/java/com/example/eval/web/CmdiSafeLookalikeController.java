package com.example.eval.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CmdiSafeLookalikeController {

    private static final String DATA_VOLUME = "/var/lib/app";

    @GetMapping("/cmdi/safe-lookalike")
    public Map<String, String> diskUsage() throws IOException, InterruptedException {
        Process process = new ProcessBuilder("sh", "-c", "df -h " + DATA_VOLUME).redirectErrorStream(true).start(); // EVAL-SAFE
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        process.waitFor();
        return Map.of("output", output);
    }
}
