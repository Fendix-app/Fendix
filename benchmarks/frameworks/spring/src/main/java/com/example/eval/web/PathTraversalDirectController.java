package com.example.eval.web;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PathTraversalDirectController {

    private static final String FILES_DIR = "/srv/app/files";

    @GetMapping("/path-traversal/direct")
    public ResponseEntity<byte[]> download(@RequestParam String file) throws IOException {
        byte[] data = Files.readAllBytes(Paths.get(FILES_DIR, file)); // EVAL-SINK
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(data);
    }
}
