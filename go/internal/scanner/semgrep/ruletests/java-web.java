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

    public void login(HttpServletResponse response) throws IOException {
        // ok: java-open_redirect-sink
        response.sendRedirect("/login");
    }
}
