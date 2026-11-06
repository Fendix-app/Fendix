package com.example.eval.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CmdiIndirectController {

    @GetMapping("/cmdi/indirect")
    public Map<String, String> ping(@RequestParam String host) throws IOException, InterruptedException {
        return Map.of("output", runPing(host));
    }

    private String runPing(String host) throws IOException, InterruptedException {
        Process process = new ProcessBuilder("sh", "-c", "ping -c 1 " + host).redirectErrorStream(true).start(); // EVAL-SINK
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        process.waitFor();
        return output;
    }
}
