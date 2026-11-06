package com.example.eval.web;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OpenRedirectSafeLookalikeController {

    private static final String DASHBOARD_PATH = "/account/dashboard";

    @GetMapping("/open-redirect/safe-lookalike")
    public void redirect(HttpServletResponse response) throws IOException {
        response.sendRedirect(DASHBOARD_PATH); // EVAL-SAFE
    }
}
