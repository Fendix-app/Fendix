package com.example.ruletests;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import javax.servlet.http.HttpServletRequest;

import freemarker.template.Configuration;
import freemarker.template.Template;
import org.apache.velocity.VelocityContext;
import org.hibernate.Session;
import org.apache.velocity.app.Velocity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.SessionAttribute;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

// ---------------------------------------------------------------- sqli

@RestController
class SqlController {

    private static final String USERS_TABLE = "users";

    private final JdbcTemplate jdbcTemplate;
    private final NamedParameterJdbcTemplate namedJdbc;
    private final EntityManager entityManager;
    private final Connection connection;

    SqlController(JdbcTemplate jdbcTemplate, NamedParameterJdbcTemplate namedJdbc, EntityManager entityManager, Connection connection) {
        this.jdbcTemplate = jdbcTemplate;
        this.namedJdbc = namedJdbc;
        this.entityManager = entityManager;
        this.connection = connection;
    }

    @GetMapping("/sql/param")
    List<Map<String, Object>> byParam(@RequestParam String name) {
        // ruleid: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }

    @GetMapping("/sql/named-param")
    List<Map<String, Object>> byNamedParam(@RequestParam("q") String name) {
        String sql = "SELECT * FROM users WHERE name LIKE '%" + name + "%'";
        // ruleid: java-sqli-taint
        return jdbcTemplate.queryForList(sql);
    }

    @GetMapping("/sql/path/{sort}")
    List<Map<String, Object>> byPath(@PathVariable String sort) {
        // ruleid: java-sqli-taint
        return jdbcTemplate.queryForList(String.format("SELECT * FROM users ORDER BY %s", sort));
    }

    @PostMapping("/sql/body")
    Map<String, Object> byBody(@RequestBody UserQuery query) {
        // ruleid: java-sqli-taint
        return jdbcTemplate.queryForMap("SELECT * FROM users WHERE email = '" + query.getEmail() + "'");
    }

    @GetMapping("/sql/header")
    int byHeader(@RequestHeader("X-Tenant") String tenant) {
        // ruleid: java-sqli-taint
        return jdbcTemplate.update("DELETE FROM sessions WHERE tenant = '" + tenant + "'");
    }

    @GetMapping("/sql/cookie")
    void byCookie(@CookieValue("region") String region) {
        // ruleid: java-sqli-taint
        jdbcTemplate.execute("SET search_path TO " + region);
    }

    @PostMapping("/sql/model")
    String byModel(@ModelAttribute UserQuery query) {
        // ruleid: java-sqli-taint
        return jdbcTemplate.queryForObject("SELECT name FROM users WHERE email = '" + query.getEmail() + "'", String.class);
    }

    @GetMapping("/sql/servlet")
    void byServlet(HttpServletRequest request) throws SQLException {
        String id = request.getParameter("id");
        Statement statement = connection.createStatement();
        // ruleid: java-sqli-taint
        statement.executeQuery("SELECT * FROM orders WHERE id = " + id);
    }

    @GetMapping("/sql/servlet-header")
    void byServletHeader(HttpServletRequest request) throws SQLException {
        Statement statement = connection.createStatement();
        // ruleid: java-sqli-taint
        statement.executeUpdate("UPDATE visits SET agent = '" + request.getHeader("User-Agent") + "'");
    }

    @GetMapping("/sql/jpa")
    List<?> byJpa(@RequestParam String name) {
        // ruleid: java-sqli-taint
        return entityManager.createQuery("SELECT u FROM User u WHERE u.name = '" + name + "'").getResultList();
    }

    @GetMapping("/sql/jpa-native")
    List<?> byJpaNative(@RequestParam String name) {
        // ruleid: java-sqli-taint
        return entityManager.createNativeQuery("SELECT * FROM users WHERE name = '" + name + "'").getResultList();
    }

    @GetMapping("/sql/batch")
    void batch(@RequestParam String name) {
        // ruleid: java-sqli-taint
        jdbcTemplate.batchUpdate("INSERT INTO audit (who) VALUES ('" + name + "')");
    }

    @GetMapping("/sql/placeholder")
    List<Map<String, Object>> placeholder(@RequestParam String name) {
        // ok: java-sqli-taint, java-sqli-sink
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = ?", name);
    }

    @GetMapping("/sql/placeholder-array")
    List<Map<String, Object>> placeholderArray(@RequestParam String name, @RequestParam String city) {
        // ok: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = ? AND city = ?", new Object[] {name, city});
    }

    @GetMapping("/sql/named")
    List<Map<String, Object>> named(@RequestParam String name) {
        // ok: java-sqli-taint
        return namedJdbc.queryForList("SELECT * FROM users WHERE name = :name", new MapSqlParameterSource("name", name));
    }

    @GetMapping("/sql/numeric/{id}")
    Map<String, Object> numeric(@PathVariable long id) {
        // ok: java-sqli-taint
        return jdbcTemplate.queryForMap("SELECT * FROM users WHERE id = " + id);
    }

    @GetMapping("/sql/constant")
    List<Map<String, Object>> constant() {
        // ok: java-sqli-taint, java-sqli-sink
        return jdbcTemplate.queryForList("SELECT * FROM " + USERS_TABLE + " ORDER BY name");
    }

    // The value reaches a helper method of this class, at the position the
    // helper builds its query from; the finding is in the helper.
    @GetMapping("/sql/helper")
    List<Map<String, Object>> viaHelper(@RequestParam String name) {
        return findByName("users", name);
    }

    // The request value goes to the helper's first parameter, which only
    // names a column alias; the query is built from the second.
    @GetMapping("/sql/helper-other-position")
    List<Map<String, Object>> viaHelperOtherPosition(@RequestParam String label) {
        // ok: java-sqli-taint
        return findByName(label, "admin");
    }

    private List<Map<String, Object>> findByName(String label, String name) {
        System.out.println(label);
        // ruleid: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }

    // A handler's plain String parameter is bound to a request parameter, and
    // an expression of request values passed to a helper is followed into it,
    // through the helper's local variable.
    @PostMapping("/sql/implicit")
    Object implicitParam(String account, String operator) throws SQLException {
        return injectableQuery(account + " " + operator);
    }

    protected Object injectableQuery(String accountName) throws SQLException {
        String query = "";
        query = "SELECT * FROM user_data WHERE last_name = '" + accountName + "'";
        Statement statement = connection.createStatement();
        // ruleid: java-sqli-taint
        return statement.executeQuery(query);
    }

    // A session attribute is set by the server, not by the request.
    @GetMapping("/sql/session")
    List<Map<String, Object>> bySession(@SessionAttribute("tenant") String tenant) {
        // ok: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM orders WHERE tenant = '" + tenant + "'");
    }

    // No handler of this class passes request input to it.
    private List<Map<String, Object>> uncalledHelper(String name) {
        // ok: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }

    private List<Map<String, Object>> byExactSql(String sql) {
        // ok: java-sqli-sink
        return jdbcTemplate.queryForList(sql);
    }
}

@RestController
class HibernateController {

    private final Session session;

    HibernateController(Session session) {
        this.session = session;
    }

    @PostMapping("/hibernate/save")
    void save(@RequestBody UserQuery user) {
        // ok: java-sqli-taint
        session.update(user);
    }

    @GetMapping("/hibernate/find")
    List<?> find(@RequestParam String name) {
        // ruleid: java-sqli-taint
        return session.createQuery("FROM User WHERE name = '" + name + "'").list();
    }
}

// The JdbcTemplate field is declared below its use, where its type is not yet
// known to Semgrep; the receiver's name still identifies it.
@RestController
class LateFieldSqlController {

    @GetMapping("/late/sql")
    List<Map<String, Object>> byName(@RequestParam String name) {
        // ruleid: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
    }

    private final JdbcTemplate jdbcTemplate = new JdbcTemplate();
}

// Fix round 1: the helper hop matches the called method by name, number of
// arguments and position, among the direct members of the handler's class.
@RestController
class HelperHopController {

    private final JdbcTemplate jdbcTemplate;
    private final EntityManager em;

    HelperHopController(JdbcTemplate jdbcTemplate, EntityManager em) {
        this.jdbcTemplate = jdbcTemplate;
        this.em = em;
    }

    // The handler calls find(String, int); find(String) has one parameter.
    @GetMapping("/hop/overload")
    List<Map<String, Object>> overload(@RequestParam String q) {
        return find(q, 20);
    }

    private List<Map<String, Object>> find(String q, int limit) {
        // ok: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name = ? LIMIT " + limit, q);
    }

    private List<Map<String, Object>> find(String column) {
        // ok: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users ORDER BY " + column);
    }

    List<Map<String, Object>> byName() {
        return find("name");
    }

    // A value escaped or reduced to a file name at the call is not followed.
    @GetMapping("/hop/sanitized")
    List<Map<String, Object>> sanitized(@RequestParam String q) {
        return lookup(Integer.toString(Integer.parseInt(q)));
    }

    private List<Map<String, Object>> lookup(String id) {
        // ok: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE id = " + id);
    }

    // The handler reassigns the value before passing it.
    @GetMapping("/hop/reassigned")
    List<Map<String, Object>> reassigned(@RequestParam String q) {
        q = q.length() > 3 ? "name" : "email";
        return order(q);
    }

    private List<Map<String, Object>> order(String column) {
        // ok: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users ORDER BY " + column);
    }

    // A format of the value is followed.
    @GetMapping("/hop/format")
    List<Map<String, Object>> formatted(@RequestParam String q) {
        return search(String.format("%s%%", q));
    }

    private List<Map<String, Object>> search(String pattern) {
        // ruleid: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE name LIKE '" + pattern + "'");
    }

    @GetMapping("/hop/second-of-three")
    List<Map<String, Object>> secondOfThree(@RequestParam String table) {
        return page(10, table, true);
    }

    private List<Map<String, Object>> page(int size, String table, boolean asc) {
        // ruleid: java-sqli-taint
        return jdbcTemplate.queryForList("SELECT * FROM " + table + " LIMIT " + size);
    }

    // A Criteria query is not SQL text.
    @GetMapping("/jpa/criteria")
    List<?> criteria(@RequestParam String name) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Object> cq = cb.createQuery(Object.class);
        Root<Object> root = cq.from(Object.class);
        // ok: java-sqli-taint
        return em.createQuery(cq.where(cb.equal(root.get("name"), name))).getResultList();
    }

    @GetMapping("/jpa/criteria-variable")
    List<?> criteriaVariable(@RequestParam String name) {
        CriteriaBuilder cb = em.getCriteriaBuilder();
        CriteriaQuery<Object> cq = cb.createQuery(Object.class);
        Root<Object> root = cq.from(Object.class);
        cq.where(cb.equal(root.get("name"), name));
        // ok: java-sqli-taint
        return em.createQuery(cq).getResultList();
    }

    // Only the method of this class, not one of a nested class, is followed.
    @GetMapping("/hop/nested")
    Object nested(@RequestParam String q) {
        return render(q, false);
    }

    private Object render(String q, boolean flag) {
        return null;
    }

    static class Renderer {
        private JdbcTemplate jdbc;

        private Object render(String table) {
            // ok: java-sqli-taint
            return jdbc.queryForList("SELECT * FROM " + table);
        }
    }
}

class UserQuery {
    private String email;

    String getEmail() {
        return email;
    }
}

@Service
class UserDirectory {

    private static final String ACTIVE_FILTER = "active = true";

    private final JdbcTemplate jdbcTemplate;

    UserDirectory(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // Called from another file with whatever a controller passes.
    public List<Map<String, Object>> findByEmail(String email) {
        // ruleid: java-sqli-sink
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE email = '" + email + "'");
    }

    public List<Map<String, Object>> findSorted(String column) {
        // ruleid: java-sqli-sink
        return jdbcTemplate.queryForList(String.format("SELECT * FROM users ORDER BY %s", column));
    }

    public List<Map<String, Object>> findActive() {
        // ok: java-sqli-sink
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE " + ACTIVE_FILTER);
    }

    public List<Map<String, Object>> findByEmailSafely(String email) {
        // ok: java-sqli-sink
        return jdbcTemplate.queryForList("SELECT * FROM users WHERE email = ?", email);
    }

    public Map<String, Object> findById(long id) {
        // ok: java-sqli-sink
        return jdbcTemplate.queryForMap("SELECT * FROM users WHERE id = " + id);
    }
}

// ---------------------------------------------------------------- cmdi

@RestController
class CommandController {

    private static final String DATA_VOLUME = "/var/lib/app";

    @GetMapping("/cmd/string")
    void execString(@RequestParam String host) throws IOException {
        // ruleid: java-cmdi-taint
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    @GetMapping("/cmd/shell-array")
    void execShellArray(@RequestParam String host) throws IOException {
        // ruleid: java-cmdi-taint
        Runtime.getRuntime().exec(new String[] {"sh", "-c", "ping -c 1 " + host});
    }

    @GetMapping("/cmd/builder")
    void builder(@RequestParam String host) throws IOException {
        // ruleid: java-cmdi-taint
        new ProcessBuilder("sh", "-c", "ping -c 1 " + host).start();
    }

    @GetMapping("/cmd/bash-list")
    void bashList(@RequestParam String host) throws IOException {
        // ruleid: java-cmdi-taint
        new ProcessBuilder(List.of("/bin/bash", "-c", "nslookup " + host)).start();
    }

    @GetMapping("/cmd/program")
    void program(HttpServletRequest request) throws IOException {
        String tool = request.getParameter("tool");
        // ruleid: java-cmdi-taint
        new ProcessBuilder(tool, "--version").start();
    }

    @GetMapping("/cmd/command")
    void command(@RequestParam String host) throws IOException {
        ProcessBuilder builder = new ProcessBuilder();
        // ruleid: java-cmdi-taint
        builder.command("bash", "-c", "traceroute " + host);
        builder.start();
    }

    @GetMapping("/cmd/helper")
    String viaHelper(@RequestParam String host) throws IOException {
        return runPing(host);
    }

    private String runPing(String host) throws IOException {
        // ruleid: java-cmdi-taint
        Process process = new ProcessBuilder("sh", "-c", "ping -c 1 " + host).start();
        return new String(process.getInputStream().readAllBytes());
    }

    @GetMapping("/cmd/argv")
    void argv(@RequestParam String host) throws IOException {
        // ok: java-cmdi-taint
        new ProcessBuilder("ping", "-c", "1", host).start();
    }

    @GetMapping("/cmd/argv-array")
    void argvArray(@RequestParam String host) throws IOException {
        // ok: java-cmdi-taint
        Runtime.getRuntime().exec(new String[] {"ping", "-c", "1", host});
    }

    @GetMapping("/cmd/constant")
    void constant() throws IOException {
        // ok: java-cmdi-taint
        new ProcessBuilder("sh", "-c", "df -h " + DATA_VOLUME).start();
    }
}

// ---------------------------------------------------------------- ssti

@RestController
class TemplateController {

    private static final String WELCOME = "Hello ${name}";

    private final Configuration freemarker;
    private final TemplateEngine templateEngine;

    TemplateController(Configuration freemarker, TemplateEngine templateEngine) {
        this.freemarker = freemarker;
        this.templateEngine = templateEngine;
    }

    @GetMapping("/tpl/freemarker")
    String freemarker(@RequestParam("template") String source) throws Exception {
        // ruleid: java-ssti-taint
        Template template = new Template("preview", new StringReader(source), freemarker);
        StringWriter out = new StringWriter();
        template.process(Map.of(), out);
        return out.toString();
    }

    @GetMapping("/tpl/velocity")
    String velocity(@RequestParam String body) {
        StringWriter out = new StringWriter();
        // ruleid: java-ssti-taint
        Velocity.evaluate(new VelocityContext(), out, "preview", body);
        return out.toString();
    }

    @PostMapping("/tpl/thymeleaf")
    String thymeleaf(HttpServletRequest request) throws IOException {
        BufferedReader reader = request.getReader();
        String body = reader.readLine();
        // ruleid: java-ssti-taint
        return templateEngine.process(body, new Context());
    }

    @GetMapping("/tpl/helper")
    String viaHelper(@RequestParam("template") String source) throws Exception {
        return render(source);
    }

    private String render(String source) throws Exception {
        // ruleid: java-ssti-taint
        Template template = new Template("preview", new StringReader(source), freemarker);
        StringWriter out = new StringWriter();
        template.process(Map.of(), out);
        return out.toString();
    }

    @GetMapping("/tpl/constant")
    String constant(@RequestParam String name) throws Exception {
        // ok: java-ssti-taint
        Template template = new Template("welcome", new StringReader(WELCOME), freemarker);
        StringWriter out = new StringWriter();
        template.process(Map.of("name", name), out);
        return out.toString();
    }

    @GetMapping("/tpl/named")
    String named(@RequestParam String name) {
        Context context = new Context();
        context.setVariable("name", name);
        // ok: java-ssti-taint
        return templateEngine.process("welcome", context);
    }
}
