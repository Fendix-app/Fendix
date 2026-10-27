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

// ---------------------------------------------------------------- xss

@RestController
class GreetingController {

    private static final String SERVICE_NAME = "Inventory";

    @GetMapping(value = "/greet", produces = MediaType.TEXT_HTML_VALUE)
    String greet(@RequestParam String name) {
        // ruleid: java-xss-taint
        return "<html><body><h1>Hello, " + name + "</h1></body></html>";
    }

    @GetMapping(value = "/greet-escaped", produces = MediaType.TEXT_HTML_VALUE)
    String greetEscaped(@RequestParam String name) {
        // ok: java-xss-taint
        return "<html><body><h1>Hello, " + HtmlUtils.htmlEscape(name) + "</h1></body></html>";
    }

    @GetMapping(value = "/greet-encoded", produces = "text/html;charset=UTF-8")
    String greetEncoded(@RequestParam String name) {
        // ok: java-xss-taint
        return "<p>" + Encode.forHtml(name) + "</p>";
    }

    @GetMapping(value = "/greet-json", produces = MediaType.APPLICATION_JSON_VALUE)
    String greetJson(@RequestParam String name) {
        // ok: java-xss-taint
        return "{\"name\": \"" + name + "\"}";
    }

    @GetMapping(value = "/status", produces = MediaType.TEXT_HTML_VALUE)
    String status() {
        // ok: java-xss-taint
        return "<h1>" + SERVICE_NAME + "</h1>";
    }

    @GetMapping("/write")
    void write(@RequestParam String name, HttpServletResponse response) throws IOException {
        response.setContentType(MediaType.TEXT_HTML_VALUE);
        // ruleid: java-xss-taint
        response.getWriter().write("<h1>Hello, " + name + "</h1>");
    }

    @GetMapping("/print")
    void print(HttpServletRequest request, HttpServletResponse response) throws IOException {
        PrintWriter out = response.getWriter();
        // ruleid: java-xss-taint
        out.println("<p>" + request.getParameter("q") + "</p>");
    }

    @GetMapping("/print-escaped")
    void printEscaped(@RequestParam String name, HttpServletResponse response) throws IOException {
        // ok: java-xss-taint
        response.getWriter().print("<p>" + StringEscapeUtils.escapeHtml4(name) + "</p>");
    }

    @GetMapping("/helper")
    void viaHelper(@RequestParam String name, HttpServletResponse response) throws IOException {
        writeGreeting(response, name);
    }

    private void writeGreeting(HttpServletResponse response, String name) throws IOException {
        // ruleid: java-xss-taint
        response.getWriter().write("<h1>Hello, " + name + "</h1>");
    }
}

// An overload taking the servlet request is not the String helper the
// handler calls; its parameter is not a source.
@RestController
class OverloadController {

    @GetMapping(value = "/basic", produces = MediaType.TEXT_HTML_VALUE)
    String basic(HttpServletRequest request) {
        String header = (String) request.getSession().getAttribute("basicAuth");
        // ok: java-xss-taint
        return "Authorization: Basic ".concat(header);
    }

    @GetMapping("/basic-check")
    boolean check(@RequestParam String user) {
        return basic(user, "secret").isEmpty();
    }

    private String basic(String user, String password) {
        return user + ":" + password;
    }
}

// Fix round 1: XSS.
@RestController
class XssRoundOneController {

    private final TemplateEngine templateEngine;

    XssRoundOneController(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    // The caller escaped the value before passing it.
    @GetMapping("/x/escaped-call")
    void escapedCall(@RequestParam String name, HttpServletResponse response) throws IOException {
        writeHtml(response, HtmlUtils.htmlEscape(name));
    }

    private void writeHtml(HttpServletResponse response, String html) throws IOException {
        // ok: java-xss-taint
        response.getWriter().write("<p>" + html + "</p>");
    }

    // A response declared JSON is not rendered as HTML.
    @GetMapping("/x/json")
    void json(@RequestParam String q, HttpServletResponse response) throws IOException {
        response.setContentType("application/json");
        // ok: java-xss-taint
        response.getWriter().write("{\"q\":\"" + q.replace("\"", "") + "\"}");
    }

    @GetMapping(value = "/x/json-produces", produces = MediaType.APPLICATION_JSON_VALUE)
    void jsonProduces(@RequestParam String q, HttpServletResponse response) throws IOException {
        // ok: java-xss-taint
        response.getWriter().write("{\"q\":\"" + q + "\"}");
    }

    // A Thymeleaf template named by a constant escapes what it renders.
    @GetMapping(value = "/x/thymeleaf", produces = MediaType.TEXT_HTML_VALUE)
    String thymeleaf(@RequestParam String name) {
        Context ctx = new Context(Locale.ENGLISH, Map.of("name", name));
        // ok: java-xss-taint
        return templateEngine.process("greeting", ctx);
    }
}

@Controller
class PageController {

    @GetMapping(value = "/page", produces = "text/html")
    @ResponseBody
    String page(@RequestParam String title) {
        // ruleid: java-xss-taint
        return "<title>" + title + "</title>";
    }

    @GetMapping("/view")
    String view(@RequestParam String title) {
        // ok: java-xss-taint
        return "greeting";
    }
}

@Component
class GreetingWriter {

    private static final String BANNER = "<h1>Welcome</h1>";

    // Called from another file with whatever a controller passes.
    public void write(HttpServletResponse response, String name) throws IOException {
        // ruleid: java-xss-sink
        response.getWriter().write("<html><body><h1>Hello, " + name + "</h1></body></html>");
    }

    public void writeBold(HttpServletResponse response, String name) throws IOException {
        // ruleid: java-xss-sink
        response.getWriter().println("Hello <b>" + name + "</b>");
    }

    public void writeBanner(HttpServletResponse response) throws IOException {
        // ok: java-xss-sink
        response.getWriter().write(BANNER);
    }

    public void writeEscaped(HttpServletResponse response, String name) throws IOException {
        // ok: java-xss-sink
        response.getWriter().write("<h1>" + HtmlUtils.htmlEscape(name) + "</h1>");
    }

    public void writeJson(HttpServletResponse response, String name) throws IOException {
        // ok: java-xss-sink
        response.getWriter().write("{\"name\": \"" + name + "\"}");
    }

    public void writeDeclaredJson(HttpServletResponse response, String name) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // ok: java-xss-sink
        response.getWriter().write("<!-- " + name + " -->");
    }
}

// ---------------------------------------------------------------- ssrf

@RestController
class FetchController {

    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");
    private static final String STATUS_URL = "https://status.example.com/api/v2/status.json";

    private final RestTemplate restTemplate = new RestTemplate();
    private final WebClient webClient = WebClient.create();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @GetMapping("/fetch")
    String fetch(@RequestParam String url) {
        // ruleid: java-ssrf-taint
        return restTemplate.getForEntity(url, String.class).getBody();
    }

    @GetMapping("/fetch-object")
    String fetchObject(@RequestParam String url) {
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @PostMapping("/fetch-post")
    String fetchPost(@RequestParam String url, @RequestParam String body) {
        // ruleid: java-ssrf-taint
        return restTemplate.postForObject(url, body, String.class);
    }

    @GetMapping("/fetch-webclient")
    String fetchWebClient(@RequestParam String url) {
        // ruleid: java-ssrf-taint
        return webClient.get().uri(url).retrieve().bodyToMono(String.class).block();
    }

    @GetMapping("/fetch-httpclient")
    String fetchHttpClient(@RequestParam String url) throws Exception {
        // ruleid: java-ssrf-taint
        return httpClient.send(HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString()).body();
    }

    @GetMapping("/fetch-url")
    String fetchUrl(HttpServletRequest request) throws IOException {
        URL target = new URL(request.getParameter("u"));
        // ruleid: java-ssrf-taint
        HttpURLConnection connection = (HttpURLConnection) target.openConnection();
        return connection.getResponseMessage();
    }

    @GetMapping("/fetch-stream")
    byte[] fetchStream(@RequestParam String url) throws IOException {
        // ruleid: java-ssrf-taint
        try (InputStream in = new URL(url).openStream()) {
            return in.readAllBytes();
        }
    }

    @GetMapping("/fetch-helper")
    String viaHelper(@RequestParam String url) {
        return fetchRemote(url);
    }

    private String fetchRemote(String url) {
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/fetch-allowed")
    String fetchAllowed(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!ALLOWED_HOSTS.contains(uri.getHost())) {
            throw new IllegalArgumentException("host not allowed");
        }
        // ok: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    // The corpus shape: the URI parsed in a try, the host checked in an ||.
    @GetMapping("/fetch-allowed-https")
    String fetchAllowedHttps(@RequestParam String url) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            return null;
        }
        if (!"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
            return null;
        }
        // ok: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    @GetMapping("/fetch-if-allowed")
    String fetchIfAllowed(@RequestParam String url) {
        URI uri = URI.create(url);
        if (ALLOWED_HOSTS.contains(uri.getHost())) {
            // ok: java-ssrf-taint
            return restTemplate.getForObject(uri, String.class);
        }
        return null;
    }

    // Only one literal URL gets through.
    @GetMapping("/fetch-exact")
    String fetchExact(@RequestParam String url) throws IOException {
        if (url.matches("http://ifconfig\\.pro")) {
            // ok: java-ssrf-taint
            try (InputStream in = new URL(url).openStream()) {
                return new String(in.readAllBytes());
            }
        }
        return null;
    }

    @GetMapping("/fetch-fixed-host")
    String fetchFixedHost(@RequestParam String user) {
        // ok: java-ssrf-taint
        return restTemplate.getForObject("https://api.example.com/users/" + user, String.class);
    }

    @GetMapping("/status")
    String status() {
        // ok: java-ssrf-taint, java-ssrf-sink
        return restTemplate.getForObject(STATUS_URL, String.class);
    }
}

// The client field is declared below its use, where its type is not yet
// known to Semgrep; the receiver's name still identifies it.
@RestController
class LateFieldController {

    @GetMapping("/late")
    String fetch(@RequestParam String url) {
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    private final RestTemplate restTemplate = new RestTemplate();
}

// Fix round 1: SSRF guards must exit, checks may be on a URI or host parsed
// from the URL, and a fixed base keeps the host.
@RestController
class SsrfRoundOneController {

    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");
    private static final Set<String> BLOCKED_HOSTS = Set.of("169.254.169.254");
    private static final String API_BASE = "https://api.example.com";

    private final RestTemplate restTemplate = new RestTemplate();
    private final WebClient webClient = WebClient.create("https://api.example.com");

    @Value("${partner.base-url}")
    private String baseUrl;

    @GetMapping("/s/denylist")
    String denylist(@RequestParam String url) {
        if (BLOCKED_HOSTS.contains(URI.create(url).getHost())) {
            throw new IllegalArgumentException("blocked");
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s/log-only")
    String logOnly(@RequestParam String url) {
        if (!ALLOWED_HOSTS.contains(URI.create(url).getHost())) {
            System.out.println("unexpected host");
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s/inside-failing-branch")
    String insideFailingBranch(@RequestParam String url) {
        if (!ALLOWED_HOSTS.contains(URI.create(url).getHost())) {
            // ruleid: java-ssrf-taint
            return restTemplate.getForObject(url, String.class);
        }
        return null;
    }

    @GetMapping("/s/parsed-then-string")
    String parsedThenString(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!ALLOWED_HOSTS.contains(uri.getHost())) {
            throw new IllegalArgumentException("host not allowed");
        }
        // ok: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s/host-variable")
    String hostVariable(@RequestParam String url) throws Exception {
        String host = new URI(url).getHost();
        if (!ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("host not allowed");
        }
        // ok: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s/unescaped-exact")
    String unescapedExact(@RequestParam String url) {
        if (!url.matches("https://api.example.com/data")) {
            throw new IllegalArgumentException("not the data URL");
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s/escaped-exact")
    String escapedExact(@RequestParam String url) {
        if (!url.matches("https://api\\.example\\.com/data")) {
            throw new IllegalArgumentException("not the data URL");
        }
        // ok: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s/constant-base/{id}")
    String constantBase(@PathVariable String id) {
        // ok: java-ssrf-taint
        return restTemplate.getForObject(API_BASE + "/users/" + id, String.class);
    }

    @GetMapping("/s/value-base/{id}")
    String valueBase(@PathVariable String id) {
        // ok: java-ssrf-taint
        return restTemplate.getForObject(baseUrl + "/users/" + id, String.class);
    }

    // A base with no separator after it lets the input extend the host.
    @GetMapping("/s/value-base-no-separator")
    String valueBaseNoSeparator(@RequestParam String suffix) {
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(baseUrl + suffix, String.class);
    }

    @GetMapping("/s/relative/{id}")
    String relative(@PathVariable String id) {
        // ok: java-ssrf-taint
        return webClient.get().uri("/users/" + id).retrieve().bodyToMono(String.class).block();
    }

    @GetMapping("/s/uri-builder/{id}")
    String uriBuilder(@PathVariable String id) {
        URI uri = UriComponentsBuilder.fromHttpUrl("https://api.example.com").path("/users/{id}").buildAndExpand(id).toUri();
        // ok: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    @GetMapping("/s/uri-builder-input")
    String uriBuilderInput(@RequestParam String url) {
        URI uri = UriComponentsBuilder.fromHttpUrl(url).path("/status").build().toUri();
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }
}

@Service
class LinkPreview {

    private static final String HEALTH_URL = "https://api.example.com/health";

    private final RestTemplate restTemplate = new RestTemplate();

    // Called from another file with whatever a controller passes.
    public String fetch(String url) {
        // ruleid: java-ssrf-sink
        return restTemplate.getForEntity(url, String.class).getBody();
    }

    public String health() {
        // ok: java-ssrf-sink
        return restTemplate.getForObject(HEALTH_URL, String.class);
    }

    public String profile(String user) {
        // ok: java-ssrf-sink
        return restTemplate.getForObject("https://api.example.com/users/" + user, String.class);
    }

    private static final Set<String> ALLOWED = Set.of("api.example.com");

    public String fetchChecked(String url) {
        if (!ALLOWED.contains(URI.create(url).getHost())) {
            throw new IllegalArgumentException("host not allowed");
        }
        // ok: java-ssrf-sink
        return restTemplate.getForObject(url, String.class);
    }

    public String fetchSchemeChecked(String url) {
        if (!"https".equals(URI.create(url).getScheme())) {
            throw new IllegalArgumentException("https only");
        }
        // ruleid: java-ssrf-sink
        return restTemplate.getForObject(url, String.class);
    }

    public String fetchLogged(String url) {
        if (!ALLOWED.contains(URI.create(url).getHost())) {
            System.out.println("unexpected host");
        }
        // ruleid: java-ssrf-sink
        return restTemplate.getForObject(url, String.class);
    }
}

// ---------------------------------------------------------------- path_traversal

@RestController
class DownloadController {

    private static final String FILES_DIR = "/srv/app/files";

    @GetMapping("/download")
    byte[] download(@RequestParam String file) throws IOException {
        // ruleid: java-path_traversal-taint
        return Files.readAllBytes(Paths.get(FILES_DIR, file));
    }

    @GetMapping("/download-stream")
    byte[] downloadStream(@RequestParam String file) throws IOException {
        // ruleid: java-path_traversal-taint
        try (InputStream in = new FileInputStream(new File(FILES_DIR, file))) {
            return in.readAllBytes();
        }
    }

    @GetMapping("/download-path-of")
    InputStream downloadPathOf(@RequestParam String file) throws IOException {
        // ruleid: java-path_traversal-taint
        return Files.newInputStream(Path.of(FILES_DIR, file));
    }

    @GetMapping("/download-reader")
    String downloadReader(HttpServletRequest request) throws IOException {
        // ruleid: java-path_traversal-taint
        try (FileReader reader = new FileReader(FILES_DIR + "/" + request.getParameter("f"))) {
            return String.valueOf(reader.read());
        }
    }

    @PostMapping("/upload")
    void upload(@RequestParam MultipartFile upload) throws IOException {
        // ruleid: java-path_traversal-taint
        upload.transferTo(new File(FILES_DIR, upload.getOriginalFilename()));
    }

    @GetMapping("/download-helper")
    byte[] viaHelper(@RequestParam String file) throws IOException {
        return readStored(file);
    }

    private byte[] readStored(String file) throws IOException {
        // ruleid: java-path_traversal-taint
        return Files.readAllBytes(Paths.get(FILES_DIR, file));
    }

    @GetMapping("/download-contained")
    byte[] downloadContained(@RequestParam String file) throws IOException {
        Path base = Paths.get(FILES_DIR).toAbsolutePath().normalize();
        Path target = base.resolve(file).normalize();
        if (!target.startsWith(base)) {
            throw new IllegalArgumentException("outside the files directory");
        }
        // ok: java-path_traversal-taint
        return Files.readAllBytes(target);
    }

    @GetMapping("/download-contained-or")
    byte[] downloadContainedOr(@RequestParam String file) throws IOException {
        Path base = Paths.get(FILES_DIR).toAbsolutePath().normalize();
        Path target = base.resolve(file).normalize();
        if (file.isEmpty() || !target.startsWith(base)) {
            throw new IllegalArgumentException("outside the files directory");
        }
        // ok: java-path_traversal-taint
        return Files.readAllBytes(target);
    }

    // Path.startsWith without normalize(): "a/../../etc" still starts with "a".
    @GetMapping("/download-not-normalized")
    byte[] downloadNotNormalized(@RequestParam String file) throws IOException {
        Path base = Paths.get(FILES_DIR);
        Path target = base.resolve(file);
        if (!target.startsWith(base)) {
            throw new IllegalArgumentException("outside the files directory");
        }
        // ruleid: java-path_traversal-taint
        return Files.readAllBytes(target);
    }

    // A string prefix check without a trailing separator lets /srv/app/files_evil through.
    @GetMapping("/download-string-prefix")
    byte[] downloadStringPrefix(@RequestParam String file) throws IOException {
        File target = new File(FILES_DIR, file);
        if (!target.getCanonicalPath().startsWith(FILES_DIR)) {
            throw new IllegalArgumentException("outside the files directory");
        }
        // ruleid: java-path_traversal-taint
        return Files.readAllBytes(target.toPath());
    }

    @GetMapping("/download-basename")
    byte[] downloadBasename(@RequestParam String file) throws IOException {
        // ok: java-path_traversal-taint
        return Files.readAllBytes(Paths.get(FILES_DIR, FilenameUtils.getName(file)));
    }

    @GetMapping("/download-filename")
    byte[] downloadFileName(@RequestParam String file) throws IOException {
        // ok: java-path_traversal-taint
        return Files.readAllBytes(Paths.get(FILES_DIR).resolve(Paths.get(file).getFileName()));
    }

    @GetMapping("/terms")
    byte[] terms() throws IOException {
        // ok: java-path_traversal-taint, java-path_traversal-sink
        return Files.readAllBytes(Paths.get(FILES_DIR, "terms.txt"));
    }
}

// Fix round 2: a host check must check the host (or one exact URL), and the
// exit must be a direct statement of the failing branch.
@RestController
class SsrfRoundTwoController {

    private static final Set<String> ALLOWED_HOSTS = Set.of("api.example.com");
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    private final RestTemplate restTemplate = new RestTemplate();
    private ExecutorService executor;
    private boolean strict;

    @GetMapping("/s2/scheme-equals")
    String schemeEquals(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!"https".equals(uri.getScheme())) {
            return null;
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    @GetMapping("/s2/scheme-allowlist")
    String schemeAllowlist(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!ALLOWED_SCHEMES.contains(uri.getScheme())) {
            throw new IllegalArgumentException("scheme");
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s2/scheme-allowlist-inline")
    String schemeAllowlistInline(@RequestParam String url) {
        if (!ALLOWED_SCHEMES.contains(URI.create(url).getScheme())) {
            throw new IllegalArgumentException("scheme");
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s2/path-allowlist")
    String pathAllowlist(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!ALLOWED_HOSTS.contains(uri.getPath())) {
            throw new IllegalArgumentException("path");
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    @GetMapping("/s2/and")
    String and(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!ALLOWED_HOSTS.contains(uri.getHost()) && strict) {
            throw new IllegalArgumentException("host");
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    @GetMapping("/s2/port-and")
    String portAnd(@RequestParam String url) {
        URI uri = URI.create(url);
        if (uri.getPort() != 443 && !ALLOWED_HOSTS.contains(uri.getHost())) {
            throw new IllegalArgumentException("host");
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    @GetMapping("/s2/lambda-return")
    String lambdaReturn(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!ALLOWED_HOSTS.contains(uri.getHost())) {
            executor.submit(() -> {
                return null;
            });
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    @GetMapping("/s2/nested-exit")
    String nestedExit(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!ALLOWED_HOSTS.contains(uri.getHost())) {
            System.out.println("host not allowed: " + uri.getHost());
            if (strict) {
                throw new IllegalArgumentException("host not allowed");
            }
        }
        // ruleid: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    @GetMapping("/s2/scheme-or-host")
    String schemeOrHost(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
            System.out.println("rejected " + url);
            throw new IllegalArgumentException("not allowed");
        }
        // ok: java-ssrf-taint
        return restTemplate.getForObject(uri, String.class);
    }

    @GetMapping("/s2/exact-url")
    String exactUrl(@RequestParam String url) {
        if (!"https://api.example.com/data".equals(url)) {
            throw new IllegalArgumentException("exact");
        }
        // ok: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s2/literal-host-inline")
    String literalHostInline(@RequestParam String url) {
        if (!"api.example.com".equals(URI.create(url).getHost())) {
            return null;
        }
        // ok: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }

    @GetMapping("/s2/literal-host-derived")
    String literalHostDerived(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!"api.example.com".equals(uri.getHost())) {
            return null;
        }
        // ok: java-ssrf-taint
        return restTemplate.getForObject(url, String.class);
    }
}

// Fix round 1: path containment must exit when it fails.
@RestController
class PathRoundOneController {

    private static final String FILES_DIR = "/srv/app/files";
    private final Path base = Paths.get(FILES_DIR).toAbsolutePath().normalize();

    @GetMapping("/p/log-only")
    byte[] logOnly(@RequestParam String file) throws IOException {
        Path target = base.resolve(file).normalize();
        if (!target.startsWith(base)) {
            System.out.println("traversal attempt " + file);
        }
        // ruleid: java-path_traversal-taint
        return Files.readAllBytes(target);
    }

    @GetMapping("/p/inside-failing-branch")
    byte[] insideFailingBranch(@RequestParam String file) throws IOException {
        Path target = base.resolve(file).normalize();
        if (!target.startsWith(base)) {
            // ruleid: java-path_traversal-taint
            return Files.readAllBytes(target);
        }
        return new byte[0];
    }

    @GetMapping("/p/contained-positive")
    byte[] containedPositive(@RequestParam String file) throws IOException {
        Path target = base.resolve(file).normalize();
        if (target.startsWith(base)) {
            // ok: java-path_traversal-taint
            return Files.readAllBytes(target);
        }
        return new byte[0];
    }

    @GetMapping("/p/canonical-variable")
    byte[] canonicalVariable(@RequestParam String file) throws IOException {
        File f = new File(FILES_DIR, file);
        String canonical = f.getCanonicalPath();
        if (!canonical.startsWith(FILES_DIR + File.separator)) {
            throw new IllegalArgumentException("outside");
        }
        // ok: java-path_traversal-taint
        return Files.readAllBytes(f.toPath());
    }

    @GetMapping("/p/canonical-variable-no-separator")
    byte[] canonicalVariableNoSeparator(@RequestParam String file) throws IOException {
        File f = new File(FILES_DIR, file);
        String canonical = f.getCanonicalPath();
        if (!canonical.startsWith(FILES_DIR)) {
            throw new IllegalArgumentException("outside");
        }
        // ruleid: java-path_traversal-taint
        return Files.readAllBytes(f.toPath());
    }

    // The caller kept only the file name, or reassigned it first.
    @GetMapping("/p/name-at-call")
    byte[] nameAtCall(@RequestParam String file) throws IOException {
        return readStored(FilenameUtils.getName(file));
    }

    @GetMapping("/p/name-reassigned")
    byte[] nameReassigned(@RequestParam String file) throws IOException {
        file = FilenameUtils.getName(file);
        return readStored2(file);
    }

    private byte[] readStored(String name) throws IOException {
        // ok: java-path_traversal-taint
        return Files.readAllBytes(Paths.get(FILES_DIR, name));
    }

    private byte[] readStored2(String name) throws IOException {
        // ok: java-path_traversal-taint
        return Files.readAllBytes(Paths.get(FILES_DIR, name));
    }
}

// Fix round 2: path.
@RestController
class PathRoundTwoController {

    private static final String FILES_DIR = "/srv/app/files";
    private final Path base = Paths.get(FILES_DIR).toAbsolutePath().normalize();
    private boolean strict;

    @GetMapping("/p2/and")
    byte[] and(@RequestParam String file) throws IOException {
        Path target = base.resolve(file).normalize();
        if (!target.startsWith(base) && strict) {
            throw new IllegalArgumentException("outside");
        }
        // ruleid: java-path_traversal-taint
        return Files.readAllBytes(target);
    }

    @GetMapping("/p2/nested-exit")
    byte[] nestedExit(@RequestParam String file) throws IOException {
        Path target = base.resolve(file).normalize();
        if (!target.startsWith(base)) {
            if (strict) {
                throw new IllegalArgumentException("outside");
            }
        }
        // ruleid: java-path_traversal-taint
        return Files.readAllBytes(target);
    }

    @GetMapping("/p2/root-base")
    byte[] rootBase(@RequestParam String file) throws IOException {
        Path target = base.resolve(file).normalize();
        if (!target.startsWith(target.getRoot())) {
            throw new IllegalArgumentException("outside");
        }
        // ruleid: java-path_traversal-taint
        return Files.readAllBytes(target);
    }
}

@Service
class DocumentStore {

    private static final String FILES_DIR = "/srv/app/files";
    private static final String INDEX = "index.json";

    // Called from another file with whatever a controller passes.
    public byte[] read(String file) throws IOException {
        // ruleid: java-path_traversal-sink
        return Files.readAllBytes(Paths.get(FILES_DIR, file));
    }

    public byte[] index() throws IOException {
        // ok: java-path_traversal-sink
        return Files.readAllBytes(Paths.get(FILES_DIR, INDEX));
    }

    public byte[] readContained(String file) throws IOException {
        // ok: java-path_traversal-sink
        Path target = Paths.get(FILES_DIR).resolve(file).normalize();
        if (!target.startsWith(Paths.get(FILES_DIR))) {
            throw new IllegalArgumentException("outside the files directory");
        }
        return Files.readAllBytes(target);
    }

    public byte[] readNestedExit(String file, boolean strict) throws IOException {
        // ruleid: java-path_traversal-sink
        Path target = Paths.get(FILES_DIR).resolve(file).normalize();
        if (!target.startsWith(Paths.get(FILES_DIR))) {
            if (strict) {
                throw new IllegalArgumentException("outside the files directory");
            }
        }
        return Files.readAllBytes(target);
    }

    public byte[] readLogged(String file) throws IOException {
        // ruleid: java-path_traversal-sink
        Path target = Paths.get(FILES_DIR).resolve(file).normalize();
        if (!target.startsWith(Paths.get(FILES_DIR))) {
            System.out.println("outside the files directory");
        }
        return Files.readAllBytes(target);
    }

    // A full path the caller chose is a file utility, not a name joined to a base directory.
    public byte[] readPath(String path) throws IOException {
        // ok: java-path_traversal-sink
        return Files.readAllBytes(Paths.get(path));
    }
}

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
