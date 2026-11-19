package com.example.eval.web;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpenRedirectIndirectController {

    @GetMapping("/open-redirect/indirect")
    public void redirect(@RequestParam String next, HttpServletResponse response) throws IOException {
        redirectTo(response, next);
    }

    private void redirectTo(HttpServletResponse response, String target) throws IOException {
        response.sendRedirect(target); // EVAL-SINK
    }
}
