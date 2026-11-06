package com.example.eval.web;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PathTraversalAltApiController {

    private static final String FILES_DIR = "/srv/app/files";

    @GetMapping("/path-traversal/alt-api")
    public ResponseEntity<byte[]> download(@RequestParam String file) throws IOException {
        try (InputStream in = new FileInputStream(new File(FILES_DIR, file))) { // EVAL-SINK
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(in.readAllBytes());
        }
    }
}
