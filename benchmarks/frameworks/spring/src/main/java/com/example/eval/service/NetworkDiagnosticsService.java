package com.example.eval.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.springframework.stereotype.Service;

@Service
public class NetworkDiagnosticsService {

    public String ping(String host) throws IOException, InterruptedException {
        Process process = new ProcessBuilder("sh", "-c", "ping -c 1 " + host).redirectErrorStream(true).start(); // EVAL-SINK
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        process.waitFor();
        return output;
    }
}
