package com.example.ruletests;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// A helper of this class whose body is one `return` of a lookup in a final
// map of literals (with a literal default), of a membership-checked
// ternary on a final set or list of literals, holds no request text whatever
// its argument. Taint is intraprocedural, so without this the call result
// would stay tainted. Every other helper shape still reports.

@RestController
class SqlConstantHelperController {

    private static final Map<String, String> COLUMNS = Map.of("name", "name", "created", "created_at");
    private static final Map<String, String> ENTRIES = Map.ofEntries(Map.entry("name", "name"), Map.entry("created", "created_at"));
    private static final Map<String, String> HASHED = new HashMap<>();
    private static final Map<String, String> NONLITERAL = Map.of("name", "name", "created", System.getenv("COL"));
    private final Map<String, String> instanceFinal = Map.of("name", "name");
    private Map<String, String> mutable = Map.of("name", "name");
    private static final Set<String> ALLOWED = Set.of("name", "created_at");
    private static final List<String> ALLOWED_LIST = List.of("name", "created_at");
    private static final Set<String> FROM_ENV = Set.of("name", System.getenv("COL"));
    private static final Set<String> FROM_COPY = new java.util.HashSet<>(List.of("name"));
    private final JdbcTemplate jdbc;

    SqlConstantHelperController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // ---- constant helpers

    private String byDefault(String k) {
        return COLUMNS.getOrDefault(k, "id");
    }

    private String byGet(String k) {
        return COLUMNS.get(k);
    }

    private String byContainsKey(String k) {
        return COLUMNS.containsKey(k) ? COLUMNS.get(k) : "id";
    }

    private String byEntries(String k) {
        return ENTRIES.getOrDefault(k, "id");
    }

    private String bySet(String k) {
        return ALLOWED.contains(k) ? k : "id";
    }

    private String byList(String k) {
        return ALLOWED_LIST.contains(k) ? k : "id";
    }

    private String byInstance(String k) {
        return instanceFinal.getOrDefault(k, "id");
    }

    private String byDefaultTwoParams(String k, String other) {
        return COLUMNS.getOrDefault(other, "id");
    }

    @GetMapping("/consthelper/default")
    List<Map<String, Object>> viaDefault(@RequestParam String sort) {
        // ok: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + byDefault(sort));
    }

    @GetMapping("/consthelper/get")
    List<Map<String, Object>> viaGet(@RequestParam String sort) {
        // ok: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + byGet(sort));
    }

    @GetMapping("/consthelper/contains-key")
    List<Map<String, Object>> viaContainsKey(@RequestParam String sort) {
        // ok: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + byContainsKey(sort));
    }

    @GetMapping("/consthelper/entries")
    List<Map<String, Object>> viaEntries(@RequestParam String sort) {
        // ok: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + byEntries(sort));
    }

    @GetMapping("/consthelper/set")
    List<Map<String, Object>> viaSet(@RequestParam String sort) {
        // ok: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + bySet(sort));
    }

    @GetMapping("/consthelper/list")
    List<Map<String, Object>> viaList(@RequestParam String sort) {
        // ok: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + byList(sort));
    }

    @GetMapping("/consthelper/instance")
    List<Map<String, Object>> viaInstance(@RequestParam String sort) {
        // ok: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + byInstance(sort));
    }

    @GetMapping("/consthelper/two-params")
    List<Map<String, Object>> viaTwoParams(@RequestParam String sort) {
        // ok: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + byDefaultTwoParams("x", sort));
    }

    @GetMapping("/consthelper/with-direction")
    List<Map<String, Object>> viaTwoHelpers(@RequestParam String sort, @RequestParam String dir) {
        // ok: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + byDefault(sort) + " " + bySet(dir));
    }

    // ---- helpers that stay tainted

    private String hashedMap(String k) {
        return HASHED.getOrDefault(k, "id");
    }

    private String mutableMap(String k) {
        return mutable.getOrDefault(k, "id");
    }

    private String nonLiteralMap(String k) {
        return NONLITERAL.getOrDefault(k, "id");
    }

    private String paramDefault(String k) {
        return COLUMNS.getOrDefault(k, k);
    }

    private String concatDefault(String k) {
        return COLUMNS.getOrDefault(k, "x" + k);
    }

    private String hashedGet(String k) {
        return HASHED.get(k);
    }

    private String ternaryParamBranch(String k) {
        return COLUMNS.containsKey(k) ? k : "id";
    }

    private String ternaryRawFallback(String k) {
        return COLUMNS.containsKey(k) ? COLUMNS.get(k) : k;
    }

    private String ternaryConcatFallback(String k) {
        return COLUMNS.containsKey(k) ? COLUMNS.get(k) : "x" + k;
    }

    private String setFromEnv(String k) {
        return FROM_ENV.contains(k) ? k : "id";
    }

    private String setFromCopy(String k) {
        return FROM_COPY.contains(k) ? k : "id";
    }

    private String setOtherBranch(String k, String other) {
        return ALLOWED.contains(k) ? other : "id";
    }

    private String setRawFallback(String k) {
        return ALLOWED.contains(k) ? k : k;
    }

    private String extraStatement(String k) {
        System.out.println(k);
        return COLUMNS.getOrDefault(k, "id");
    }

    private String guardedReturn(String k) {
        if (ALLOWED.contains(k)) return k;
        return "id";
    }

    private String mixedReturns(String k) {
        if (k.isEmpty()) {
            return "id";
        }
        return COLUMNS.getOrDefault(k, "id");
    }

    private String literalAndParam(String k) {
        if (k.isEmpty()) {
            return "id";
        }
        return k;
    }

    private String lookupThenConcat(String k) {
        return COLUMNS.getOrDefault(k, "id") + k;
    }

    // Two methods of one name: the call may reach either, so one raw return
    // keeps the call tainted.
    private String overloaded(String k) {
        return COLUMNS.getOrDefault(k, "id");
    }

    private String overloaded(String k, String fallback) {
        return fallback;
    }

    @GetMapping("/consthelper/hashed")
    List<Map<String, Object>> viaHashed(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + hashedMap(sort));
    }

    @GetMapping("/consthelper/mutable")
    List<Map<String, Object>> viaMutable(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + mutableMap(sort));
    }

    @GetMapping("/consthelper/non-literal")
    List<Map<String, Object>> viaNonLiteral(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + nonLiteralMap(sort));
    }

    @GetMapping("/consthelper/param-default")
    List<Map<String, Object>> viaParamDefault(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + paramDefault(sort));
    }

    @GetMapping("/consthelper/concat-default")
    List<Map<String, Object>> viaConcatDefault(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + concatDefault(sort));
    }

    @GetMapping("/consthelper/hashed-get")
    List<Map<String, Object>> viaHashedGet(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + hashedGet(sort));
    }

    @GetMapping("/consthelper/ternary-param-branch")
    List<Map<String, Object>> viaTernaryParamBranch(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + ternaryParamBranch(sort));
    }

    @GetMapping("/consthelper/ternary-raw-fallback")
    List<Map<String, Object>> viaTernaryRawFallback(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + ternaryRawFallback(sort));
    }

    @GetMapping("/consthelper/ternary-concat-fallback")
    List<Map<String, Object>> viaTernaryConcatFallback(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + ternaryConcatFallback(sort));
    }

    @GetMapping("/consthelper/set-from-env")
    List<Map<String, Object>> viaSetFromEnv(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + setFromEnv(sort));
    }

    @GetMapping("/consthelper/set-from-copy")
    List<Map<String, Object>> viaSetFromCopy(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + setFromCopy(sort));
    }

    @GetMapping("/consthelper/set-other-branch")
    List<Map<String, Object>> viaSetOtherBranch(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + setOtherBranch("name", sort));
    }

    @GetMapping("/consthelper/set-raw-fallback")
    List<Map<String, Object>> viaSetRawFallback(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + setRawFallback(sort));
    }

    @GetMapping("/consthelper/extra-statement")
    List<Map<String, Object>> viaExtraStatement(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + extraStatement(sort));
    }

    @GetMapping("/consthelper/guarded-return")
    List<Map<String, Object>> viaGuardedReturn(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + guardedReturn(sort));
    }

    @GetMapping("/consthelper/mixed-returns")
    List<Map<String, Object>> viaMixedReturns(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + mixedReturns(sort));
    }

    @GetMapping("/consthelper/literal-and-param")
    List<Map<String, Object>> viaLiteralAndParam(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + literalAndParam(sort));
    }

    @GetMapping("/consthelper/lookup-then-concat")
    List<Map<String, Object>> viaLookupThenConcat(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + lookupThenConcat(sort));
    }

    @GetMapping("/consthelper/overloaded")
    List<Map<String, Object>> viaOverloaded(@RequestParam String sort) {
        // ruleid: java-sqli-taint
        return jdbc.queryForList("SELECT * FROM t ORDER BY " + overloaded("x", sort));
    }
}
