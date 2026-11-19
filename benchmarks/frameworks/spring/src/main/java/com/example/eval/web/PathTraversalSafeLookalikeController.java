package com.example.eval.web;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PathTraversalSafeLookalikeController {

    private static final String FILES_DIR = "/srv/app/files";

    @GetMapping("/path-traversal/safe-lookalike")
    public ResponseEntity<byte[]> termsOfService() throws IOException {
        byte[] data = Files.readAllBytes(Paths.get(FILES_DIR, "terms-of-service.txt")); // EVAL-SAFE
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(data);
    }
}
