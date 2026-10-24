package com.example.eval.web;

import java.io.IOException;

import com.example.eval.service.DocumentStorageService;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class PathTraversalCrossFileController {

    private final DocumentStorageService documentStorageService;

    public PathTraversalCrossFileController(DocumentStorageService documentStorageService) {
        this.documentStorageService = documentStorageService;
    }

    @GetMapping("/path-traversal/cross-file")
    public ResponseEntity<byte[]> download(@RequestParam String file) throws IOException {
        byte[] data = documentStorageService.read(file);
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_OCTET_STREAM).body(data);
    }
}
