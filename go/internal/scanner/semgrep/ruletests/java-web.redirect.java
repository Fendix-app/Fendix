package com.example.ruletests;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import java.util.Locale;
import java.util.Map;

// Open redirect cases, apart from java-web.java and in two files: semgrep --test
// runs each rule under a fixed 5 s per-file timeout, and the cost of
// java-open_redirect-taint grows with the file, so over the whole of
// java-web.java it ran past that limit on a CI runner and reported no match.
// The sink rule's cases share java-web.redirect.java with RedirectController,
// whose ok: line names the sink rule too.

// ---------------------------------------------------------------- open_redirect

@Controller
class RedirectController {

    private static final String DASHBOARD = "/account/dashboard";

    @GetMapping("/go")
    void go(@RequestParam String next, HttpServletResponse response) throws IOException {
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/go-view")
    String goView(@RequestParam String next) {
        // ruleid: java-open_redirect-taint
        return "redirect:" + next;
    }

    @GetMapping("/go-entity")
    ResponseEntity<Void> goEntity(@RequestParam String next) {
        // ruleid: java-open_redirect-taint
        return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(next)).build();
    }

    @GetMapping("/go-headers")
    ResponseEntity<Void> goHeaders(@RequestParam String next) {
        HttpHeaders headers = new HttpHeaders();
        // ruleid: java-open_redirect-taint
        headers.setLocation(URI.create(next));
        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @GetMapping("/go-redirect-view")
    RedirectView goRedirectView(HttpServletRequest request) {
        // ruleid: java-open_redirect-taint
        return new RedirectView(request.getParameter("next"));
    }

    @GetMapping("/go-model-and-view")
    ModelAndView goModelAndView(@RequestParam String next) {
        // ruleid: java-open_redirect-taint
        return new ModelAndView("redirect:" + next);
    }

    @GetMapping("/go-helper")
    void viaHelper(@RequestParam String next, HttpServletResponse response) throws IOException {
        redirectTo(response, next);
    }

    private void redirectTo(HttpServletResponse response, String target) throws IOException {
        // ruleid: java-open_redirect-taint
        response.sendRedirect(target);
    }

    @GetMapping("/go-local")
    void goLocal(@RequestParam String next, HttpServletResponse response) throws IOException {
        String target = next;
        if (!target.startsWith("/") || target.startsWith("//") || target.startsWith("/\\")) {
            target = "/";
        }
        // ok: java-open_redirect-taint
        response.sendRedirect(target);
    }

    @GetMapping("/go-local-or-null")
    void goLocalOrNull(@RequestParam(required = false) String next, HttpServletResponse response) throws IOException {
        String target = next;
        if (target == null || !target.startsWith("/") || target.startsWith("//")) {
            target = "/";
        }
        // ok: java-open_redirect-taint
        response.sendRedirect(target);
    }

    @GetMapping("/go-user")
    String goUser(@RequestParam String name) {
        // ok: java-open_redirect-taint
        return "redirect:/users/" + name;
    }

    @GetMapping("/go-dashboard")
    void goDashboard(HttpServletResponse response) throws IOException {
        // ok: java-open_redirect-taint, java-open_redirect-sink
        response.sendRedirect(DASHBOARD);
    }
}

// Fix round 1: a local-path check needs both halves and must exit, replace
// the target, or surround the use.
@Controller
class RedirectRoundOneController {

    @GetMapping("/r/slash-slash-only")
    void slashSlashOnly(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (next.startsWith("//")) {
            throw new IllegalArgumentException("protocol-relative");
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r/view-slash-slash-only")
    String viewSlashSlashOnly(@RequestParam String next) {
        if (next.startsWith("//")) {
            return "redirect:/";
        }
        // ruleid: java-open_redirect-taint
        return "redirect:" + next;
    }

    @GetMapping("/r/slash-only")
    void slashOnly(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/")) {
            next = "/";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r/inverted")
    void inverted(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (next.startsWith("//")) {
            // ruleid: java-open_redirect-taint
            response.sendRedirect(next);
            return;
        }
        response.sendRedirect("/");
    }

    @GetMapping("/r/log-only")
    void logOnly(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            System.out.println("suspicious redirect " + next);
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r/exits")
    void exits(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            throw new IllegalArgumentException("not a local path");
        }
        // ok: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r/positive")
    void positive(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (next.startsWith("/") && !next.startsWith("//")) {
            // ok: java-open_redirect-taint
            response.sendRedirect(next);
            return;
        }
        response.sendRedirect("/");
    }

    @GetMapping("/r/settings")
    String settings(@RequestParam String tab) {
        String view = "redirect:/settings/" + tab;
        // ok: java-open_redirect-taint
        return view;
    }
}

@Service
class Redirects {

    private static final String HOME = "/";

    // Called from another file with whatever a controller passes.
    public void redirectTo(HttpServletResponse response, String target) throws IOException {
        // ruleid: java-open_redirect-sink
        response.sendRedirect(target);
    }

    public void home(HttpServletResponse response) throws IOException {
        // ok: java-open_redirect-sink
        response.sendRedirect(HOME);
    }

    public void redirectLocal(HttpServletResponse response, String target) throws IOException {
        if (!target.startsWith("/") || target.startsWith("//")) {
            target = "/";
        }
        // ok: java-open_redirect-sink
        response.sendRedirect(target);
    }

    public void redirectNotLiteral(HttpServletResponse response, String target) throws IOException {
        if (!target.startsWith("/") || target.startsWith("//")) {
            target = target.substring(1);
        }
        // ruleid: java-open_redirect-sink
        response.sendRedirect(target);
    }

    public void redirectReplacedWhenStrict(HttpServletResponse response, String target, boolean strict) throws IOException {
        String reason;
        if (!target.startsWith("/") || target.startsWith("//")) {
            if (strict) target = "/";
            reason = "bad-target";
        }
        // ruleid: java-open_redirect-sink
        response.sendRedirect(target);
    }

    public void redirectReplacedThenNoted(HttpServletResponse response, String target) throws IOException {
        String reason;
        if (!target.startsWith("/") || target.startsWith("//")) {
            target = "/";
            reason = "bad-target";
        }
        // ok: java-open_redirect-sink
        response.sendRedirect(target);
    }

    public void redirectAnotherReplaced(HttpServletResponse response, String target, String fallback) throws IOException {
        if (!target.startsWith("/") || target.startsWith("//") || fallback.startsWith("//")) {
            fallback = "/";
        }
        // ruleid: java-open_redirect-sink
        response.sendRedirect(target);
    }

    public void redirectReplacedOnElse(HttpServletResponse response, String target) throws IOException {
        String reason;
        if (!target.startsWith("/") || target.startsWith("//")) {
            reason = "bad-target";
        } else {
            target = "/";
        }
        // ruleid: java-open_redirect-sink
        response.sendRedirect(target);
    }

    public void redirectInverted(HttpServletResponse response, String target) throws IOException {
        if (target.startsWith("//")) {
            // ruleid: java-open_redirect-sink
            response.sendRedirect(target);
            return;
        }
        response.sendRedirect("/");
    }

    public void login(HttpServletResponse response) throws IOException {
        // ok: java-open_redirect-sink
        response.sendRedirect("/login");
    }
}
