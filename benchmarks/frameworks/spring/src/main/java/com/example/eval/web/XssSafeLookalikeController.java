package com.example.eval.web;

import java.time.Instant;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class XssSafeLookalikeController {

    private static final String SERVICE_NAME = "Inventory Service";

    @GetMapping(value = "/xss/safe-lookalike", produces = MediaType.TEXT_HTML_VALUE)
    public String status() {
        return "<html><body><h1>" + SERVICE_NAME + "</h1><p>Server time: " + Instant.now() + "</p></body></html>"; // EVAL-SAFE
    }
}
