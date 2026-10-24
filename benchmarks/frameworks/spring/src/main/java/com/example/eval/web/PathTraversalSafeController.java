package com.example.eval.web;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PathTraversalSafeController {

    private static final String FILES_DIR = "/srv/app/files";

    @GetMapping("/path-traversal/safe")
    public ResponseEntity<byte[]> download(@RequestParam String file) throws IOException {
        Path base = Paths.get(FILES_DIR).toAbsolutePath().normalize();
        Path target = base.resolve(file).normalize();
        if (!target.startsWith(base)) {
            return ResponseEntity.badRequest().build();
        }
        byte[] data = Files.readAllBytes(target); // EVAL-SAFE
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(data);
    }
}
