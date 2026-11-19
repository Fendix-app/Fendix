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

// Fix round 2: a direct exit or literal replacement, and both halves with
// their own polarity.
@Controller
class RedirectRoundTwoController {

    private ExecutorService executor;
    private boolean strict;

    @GetMapping("/r2/literal-unbraced")
    void literalUnbraced(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) next = "/";
        // ok: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r2/not-literal-unbraced")
    void notLiteralUnbraced(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) next = next.substring(1);
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r2/not-literal")
    void notLiteral(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            next = next.substring(1);
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r2/and")
    void and(@RequestParam String next, HttpServletResponse response) throws IOException {
        if ((!next.startsWith("/") || next.startsWith("//")) && strict) {
            next = "/";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r2/slash-half-under-and")
    void slashHalfUnderAnd(@RequestParam String next, HttpServletResponse response) throws IOException {
        if ((!next.startsWith("/") && strict) || next.startsWith("//")) {
            next = "/";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r2/lambda-return")
    void lambdaReturn(@RequestParam String next, HttpServletResponse response) throws Exception {
        if (!next.startsWith("/") || next.startsWith("//")) {
            executor.submit(() -> {
                return null;
            });
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r2/nested-replace")
    void nestedReplace(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            if (strict) {
                next = "/";
            }
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r2/nested-throw")
    void nestedThrow(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            if (strict) {
                throw new IllegalArgumentException("bad");
            }
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r2/external-only")
    void externalOnly(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") && !next.startsWith("//")) {
            // ruleid: java-open_redirect-taint
            response.sendRedirect(next);
        }
    }
}

// Fix round 3: the replacement or exit must be the failing branch's own last
// statement, and a replacement must assign the guarded target.
@Controller
class RedirectRoundThreeController {

    private boolean strict;
    private String reason;

    @GetMapping("/r3/replace-when-strict")
    void replaceWhenStrict(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            if (strict) next = "/";
            reason = "bad-target";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r3/return-when-strict")
    void returnWhenStrict(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            if (strict) return;
            reason = "bad-target";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r3/throw-when-strict")
    void throwWhenStrict(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            if (strict) throw new IllegalArgumentException("bad");
            reason = "bad-target";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r3/note-then-replace")
    void noteThenReplace(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            reason = "bad-target";
            next = "/";
        }
        // ok: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r3/replace-then-note")
    void replaceThenNote(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            next = "/";
            reason = "bad-target";
        }
        // ok: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r3/replace-another")
    void replaceAnother(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            reason = "/";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }
}

// Fix round 4: the replacing if has no else, and the value it replaces is
// the one its condition tests with startsWith("//").
@Controller
class RedirectRoundFourController {

    private String reason;

    @GetMapping("/r4/third-term-replaced")
    void thirdTermReplaced(@RequestParam String next, @RequestParam String other, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//") || other.startsWith("//")) other = "/";
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r4/first-term-replaced")
    void firstTermReplaced(@RequestParam String next, @RequestParam String other, HttpServletResponse response) throws IOException {
        if (other.startsWith("//") || !next.startsWith("/") || next.startsWith("//")) {
            other = "/";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r4/replaced-on-else")
    void replacedOnElse(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            reason = "bad";
        } else {
            next = "/";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r4/replaced-on-else-if")
    void replacedOnElseIf(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            reason = "bad";
        } else if (next.length() > 100) {
            next = "/";
        }
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r4/replaced-on-unbraced-else")
    void replacedOnUnbracedElse(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) reason = "bad"; else next = "/";
        // ruleid: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r4/replaced-with-else")
    void replacedWithElse(@RequestParam String next, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) next = "/"; else reason = "ok";
        // An if with an else is not taken as a replacement guard, even when
        // the replacement is on the failing branch.
        // todook: java-open_redirect-taint
        response.sendRedirect(next);
    }

    @GetMapping("/r4/raw-then-literal")
    void rawThenLiteral(@RequestParam String next, @RequestParam String fallback, HttpServletResponse response) throws IOException {
        if (!next.startsWith("/") || next.startsWith("//")) {
            next = fallback;
            next = "/";
        }
        // ok: java-open_redirect-taint
        response.sendRedirect(next);
    }
}
