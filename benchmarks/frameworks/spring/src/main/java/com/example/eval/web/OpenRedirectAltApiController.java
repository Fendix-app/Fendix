package com.example.eval.web;

import java.net.URI;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpenRedirectAltApiController {

    @GetMapping("/open-redirect/alt-api")
    public ResponseEntity<Void> redirect(@RequestParam String next) {
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(next)).build(); // EVAL-SINK
    }
}
