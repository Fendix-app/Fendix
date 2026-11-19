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
public class SstiIndirectController {

    private final Configuration freemarkerConfiguration;

    public SstiIndirectController(Configuration freemarkerConfiguration) {
        this.freemarkerConfiguration = freemarkerConfiguration;
    }

    @GetMapping(value = "/ssti/indirect", produces = MediaType.TEXT_PLAIN_VALUE)
    public String preview(@RequestParam("template") String source, @RequestParam String name)
            throws IOException, TemplateException {
        return renderPreview(source, name);
    }

    private String renderPreview(String source, String name) throws IOException, TemplateException {
        Template template = new Template("preview", new StringReader(source), freemarkerConfiguration); // EVAL-SINK
        StringWriter out = new StringWriter();
        template.process(Map.of("name", name), out);
        return out.toString();
    }
}
