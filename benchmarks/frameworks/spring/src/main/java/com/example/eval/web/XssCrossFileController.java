package com.example.eval.web;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;

import com.example.eval.service.GreetingPageWriter;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class XssCrossFileController {

    private final GreetingPageWriter greetingPageWriter;

    public XssCrossFileController(GreetingPageWriter greetingPageWriter) {
        this.greetingPageWriter = greetingPageWriter;
    }

    @GetMapping("/xss/cross-file")
    public void greet(@RequestParam String name, HttpServletResponse response) throws IOException {
        greetingPageWriter.write(response, name);
    }
}
