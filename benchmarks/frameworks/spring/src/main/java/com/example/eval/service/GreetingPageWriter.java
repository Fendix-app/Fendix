package com.example.eval.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

@Component
public class GreetingPageWriter {

    public void write(HttpServletResponse response, String name) throws IOException {
        response.setContentType(MediaType.TEXT_HTML_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("<html><body><h1>Hello, " + name + "</h1></body></html>"); // EVAL-SINK
    }
}
