package semgrep

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ruleFixture is one Python file and the bundled rule it exercises: the rule
// must fire on it when fires is true and stay silent when false.
type ruleFixture struct {
	rule  string
	file  string
	fires bool
	body  string
}

// ruleBehaviourFixtures pins what the four injection/auth rules repaired in
// v3.6.3 actually match. Each one listed its alternatives as sibling
// `pattern:` entries under `patterns:`, which Semgrep ANDs, so none of them
// could ever fire; these fixtures were red against that rule pack.
var ruleBehaviourFixtures = []ruleFixture{
	// python-eval-injection: eval()/exec() with a non-literal argument.
	{"python-eval-injection", "eval_dynamic.py", true, "def run(user_input):\n    return eval(user_input)\n"},
	{"python-eval-injection", "exec_dynamic.py", true, "def run(user_code):\n    exec(user_code)\n"},
	{"python-eval-injection", "eval_with_globals.py", true, "def run(expr, env):\n    return eval(expr, env)\n"},
	{"python-eval-injection", "eval_literal.py", false, "def run():\n    return eval(\"2 + 2\")\n"},
	{"python-eval-injection", "exec_literal.py", false, "def run():\n    exec(\"x = 1\")\n"},
	{"python-eval-injection", "literal_eval.py", false, "import ast\ndef run(user_input):\n    return ast.literal_eval(user_input)\n"},

	// python-jwt-decode-no-verification: signature verification disabled, or "none" allowed.
	{"python-jwt-decode-no-verification", "jwt_verify_false.py", true, "import jwt\ndef read(token):\n    return jwt.decode(token, options={\"verify_signature\": False})\n"},
	{"python-jwt-decode-no-verification", "jwt_verify_false_with_key.py", true, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, algorithms=[\"HS256\"], options={\"verify_signature\": False})\n"},
	{"python-jwt-decode-no-verification", "jwt_verify_false_among_options.py", true, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, options={\"verify_exp\": True, \"verify_signature\": False})\n"},
	{"python-jwt-decode-no-verification", "jwt_alg_none.py", true, "import jwt\ndef read(token):\n    return jwt.decode(token, algorithms=[\"none\"])\n"},
	{"python-jwt-decode-no-verification", "jwt_alg_none_with_key.py", true, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, algorithms=[\"HS256\", \"none\"])\n"},
	{"python-jwt-decode-no-verification", "jwt_verified.py", false, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, algorithms=[\"HS256\"])\n"},
	{"python-jwt-decode-no-verification", "jwt_other_option.py", false, "import jwt\ndef read(token, key):\n    return jwt.decode(token, key, algorithms=[\"HS256\"], options={\"verify_exp\": False})\n"},

	// python-sql-injection-string-format: a query built by formatting, passed to execute().
	{"python-sql-injection-string-format", "sql_percent.py", true, "def q(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = %s\" % uid)\n"},
	{"python-sql-injection-string-format", "sql_concat.py", true, "def q(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = \" + uid)\n"},
	{"python-sql-injection-string-format", "sql_fstring.py", true, "def q(cursor, uid):\n    cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n"},
	{"python-sql-injection-string-format", "sql_format_method.py", true, "def q(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = {}\".format(uid))\n"},
	{"python-sql-injection-string-format", "sql_parameterised.py", false, "def q(cursor, uid):\n    cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))\n"},
	{"python-sql-injection-string-format", "sql_literal_concat.py", false, "def q(cursor):\n    cursor.execute(\"SELECT * FROM users \" + \"WHERE active = 1\")\n"},
	// An f-string whose interpolations are all string constants builds no
	// injectable query; a constant must not hide a value from input beside
	// it, a local that rebinds it, or a query built another way.
	{"python-sql-injection-string-format", "sql_const_table.py", false, "USERS_TABLE = \"users\"\ndef h(cur):\n    cur.execute(f\"SELECT id FROM {USERS_TABLE}\")\n"},
	{"python-sql-injection-string-format", "sql_local_const.py", false, "def h(cur):\n    table = \"users\"\n    cur.execute(f\"SELECT id FROM {table}\")\n"},
	{"python-sql-injection-string-format", "sql_var.py", true, "def h(cur, name):\n    cur.execute(f\"SELECT id FROM users WHERE n = '{name}'\")\n"},
	{"python-sql-injection-string-format", "sql_upper_tainted.py", true, "from flask import request\ndef h(cur):\n    QUERY = request.args[\"q\"]\n    cur.execute(f\"SELECT id FROM users WHERE n = '{QUERY}'\")\n"},
	{"python-sql-injection-string-format", "sql_mixed_const_and_var.py", true, "COLS = \"id, name\"\ndef h(cur, name):\n    cur.execute(f\"SELECT {COLS} FROM users WHERE n = '{name}'\")\n"},
	{"python-sql-injection-string-format", "sql_const_shadowed_by_local.py", true, "from flask import request\nTABLE = \"users\"\ndef h(cur):\n    TABLE = request.args[\"t\"]\n    cur.execute(f\"SELECT id FROM {TABLE}\")\n"},
	{"python-sql-injection-string-format", "sql_const_rebound_conditionally.py", true, "def h(cur, name):\n    where = \"\"\n    if name:\n        where = f\"WHERE n = '{name}'\"\n    cur.execute(f\"SELECT id FROM users {where}\")\n"},
	{"python-sql-injection-string-format", "sql_percent_beside_const.py", true, "TABLE = \"users\"\ndef h(cur, name):\n    cur.execute(\"SELECT id FROM users WHERE n = '%s'\" % name)\n"},

	// python-command-injection-shell-true: os.system / os.popen with a non-literal command.
	{"python-command-injection-shell-true", "os_system_var.py", true, "import os\ndef go(cmd):\n    os.system(cmd)\n"},
	{"python-command-injection-shell-true", "os_system_fstring.py", true, "import os\ndef go(path):\n    os.system(f\"ls {path}\")\n"},
	{"python-command-injection-shell-true", "os_popen_var.py", true, "import os\ndef go(cmd):\n    return os.popen(cmd).read()\n"},
	{"python-command-injection-shell-true", "os_system_literal.py", false, "import os\ndef go():\n    os.system(\"ls -la\")\n"},
	{"python-command-injection-shell-true", "argv_list.py", false, "import subprocess\ndef go(path):\n    subprocess.run([\"ls\", path])\n"},
	// subprocess(..., shell=True) is python-subprocess-shell-true-with-variable's;
	// this rule must not report the same call a second time.
	{"python-command-injection-shell-true", "subprocess_shell_var.py", false, "import subprocess\ndef go(cmd):\n    subprocess.run(cmd, shell=True)\n"},
	{"python-subprocess-shell-true-with-variable", "subprocess_shell_var.py", true, ""},
}

// requireSemgrep returns the semgrep binary, or skips the test when it is not
// installed. CI's semgrep-enabled job sets FENDIX_REQUIRE_SEMGREP=1 so a
// missing binary fails the job instead of passing it silently.
func requireSemgrep(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("semgrep")
	if err == nil {
		return bin
	}
	if os.Getenv("FENDIX_REQUIRE_SEMGREP") != "" {
		t.Fatalf("FENDIX_REQUIRE_SEMGREP is set but semgrep is not on PATH: %v", err)
	}
	t.Skip("semgrep not on PATH; skipping rule-behaviour test")
	return ""
}

// TestRuleBehaviour_RepairedRulesMatchTheirIntent runs the bundled rule pack
// over the fixtures above and checks each expectation.
func TestRuleBehaviour_RepairedRulesMatchTheirIntent(t *testing.T) {
	bin := requireSemgrep(t)
	resetRulesCacheForTesting()
	dir, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}

	root := t.TempDir()
	for _, f := range ruleBehaviourFixtures {
		if f.body == "" {
			continue // shares another fixture's file
		}
		if err := os.WriteFile(filepath.Join(root, f.file), []byte(f.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command(bin, "scan", "--config", dir, "--json", "--no-git-ignore", "--metrics=off", "--disable-version-check", root)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// semgrep exits 1 when it finds matches; the JSON envelope is still valid.
	out, _ := cmd.Output()
	// A key Semgrep does not recognise is dropped with only a warning: the
	// rule loads and silently loses that clause. A top-level pattern-not and
	// pattern-not-inside sat outside `patterns:` this way until v3.6.3.
	for _, line := range strings.Split(stderr.String(), "\n") {
		if strings.Contains(line, "Skipping unknown field") {
			t.Errorf("bundled rule has a clause Semgrep ignores: %s", strings.TrimSpace(line))
		}
	}
	var res struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
		} `json:"results"`
		Errors []json.RawMessage `json:"errors"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("parse semgrep json: %v\noutput:\n%s", err, string(out))
	}
	if len(res.Errors) > 0 {
		t.Fatalf("semgrep reported %d rule/parse errors: %s", len(res.Errors), res.Errors[0])
	}

	fired := map[string]map[string]bool{} // file -> rule ids
	for _, r := range res.Results {
		file := filepath.Base(r.Path)
		if fired[file] == nil {
			fired[file] = map[string]bool{}
		}
		fired[file][r.CheckID[strings.LastIndex(r.CheckID, ".")+1:]] = true
	}
	for _, f := range ruleBehaviourFixtures {
		if got := fired[f.file][f.rule]; got != f.fires {
			var rules []string
			for id := range fired[f.file] {
				rules = append(rules, id)
			}
			sort.Strings(rules)
			t.Errorf("%s on %s: fired=%v, want %v (rules that fired: %v)", f.rule, f.file, got, f.fires, rules)
		}
	}
}
