package com.example.eval.web;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class XssSafeController {

    @GetMapping(value = "/xss/safe", produces = MediaType.TEXT_HTML_VALUE)
    public String greet(@RequestParam String name) {
        return "<html><body><h1>Hello, " + HtmlUtils.htmlEscape(name) + "</h1></body></html>"; // EVAL-SAFE
    }
}
