package com.example.eval.web;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SstiSafeLookalikeController {

    private static final String MAINTENANCE_TEMPLATE = "${service} maintenance window starts at ${start}.";

    private final Configuration freemarkerConfiguration;

    public SstiSafeLookalikeController(Configuration freemarkerConfiguration) {
        this.freemarkerConfiguration = freemarkerConfiguration;
    }

    @GetMapping(value = "/ssti/safe-lookalike", produces = MediaType.TEXT_PLAIN_VALUE)
    public String maintenanceNotice() throws IOException, TemplateException {
        Template template = new Template("maintenance", new StringReader(MAINTENANCE_TEMPLATE), freemarkerConfiguration); // EVAL-SAFE
        StringWriter out = new StringWriter();
        template.process(Map.of(
                "service", "Inventory Service",
                "start", Instant.now().plus(Duration.ofHours(2)).toString()), out);
        return out.toString();
    }
}
