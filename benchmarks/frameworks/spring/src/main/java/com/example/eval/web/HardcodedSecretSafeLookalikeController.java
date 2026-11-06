package com.example.eval.web;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HardcodedSecretSafeLookalikeController {

    private static final String BUILD_DIGEST = "4b1d6e0f9a7c3e5d2b8f6a1c0e9d7b3a5f2c8e6d4a1b9f7c3e0d5a2b8c6f4e19"; // EVAL-SAFE

    @GetMapping("/hardcoded-secret/safe-lookalike")
    public Map<String, String> buildInfo() {
        return Map.of("service", "eval-spring", "buildDigest", BUILD_DIGEST);
    }
}
