package com.example.eval.web;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Map;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SstiSafeController {

    private static final String WELCOME_TEMPLATE = "Hello ${name}, thanks for signing up.";

    private final Configuration freemarkerConfiguration;

    public SstiSafeController(Configuration freemarkerConfiguration) {
        this.freemarkerConfiguration = freemarkerConfiguration;
    }

    @GetMapping(value = "/ssti/safe", produces = MediaType.TEXT_PLAIN_VALUE)
    public String preview(@RequestParam String name) throws IOException, TemplateException {
        Template template = new Template("welcome", new StringReader(WELCOME_TEMPLATE), freemarkerConfiguration); // EVAL-SAFE
        StringWriter out = new StringWriter();
        template.process(Map.of("name", name), out);
        return out.toString();
    }
}
