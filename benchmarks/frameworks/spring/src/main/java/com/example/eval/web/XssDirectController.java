package com.example.eval.web;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class XssDirectController {

    @GetMapping(value = "/xss/direct", produces = MediaType.TEXT_HTML_VALUE)
    public String greet(@RequestParam String name) {
        return "<html><body><h1>Hello, " + name + "</h1></body></html>"; // EVAL-SINK
    }
}
