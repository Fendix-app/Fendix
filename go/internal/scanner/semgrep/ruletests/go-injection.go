//go:build ignore

// Rule tests for rules/go-injection.yaml: SQL injection, command injection and
// server-side template injection in net/http and Gin handlers. See README.md.
package ruletests

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"text/template"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"github.com/open-policy-agent/opa/rego"
	"gorm.io/gorm"
)

var db *sql.DB

var sqlxDB *sqlx.DB

var gormDB *gorm.DB

const usersTable = "users"

const (
	auditTable = "audit_log"
	dataVolume = "/var/lib/app"
)

const welcomeTemplate = "Hello {{.Name}}, thanks for signing up."

// --- SQL injection ------------------------------------------------------------

func sqliNetHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: go-sqli-taint
	rows, err := db.Query(fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name))
	if err != nil {
		return
	}
	defer rows.Close()
	// ruleid: go-sqli-taint
	db.QueryRowContext(r.Context(), "SELECT id FROM users WHERE name = '"+name+"'")
	stmt := "DELETE FROM sessions WHERE owner = '" + r.FormValue("owner") + "'"
	// ruleid: go-sqli-taint
	db.Exec(stmt)
	// ok: go-sqli-taint
	db.Query("SELECT id FROM users WHERE name = $1", name)
	// ok: go-sqli-taint
	db.QueryRow("SELECT id FROM users WHERE name = ?", name)
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		return
	}
	// ok: go-sqli-taint
	db.Query(fmt.Sprintf("SELECT name FROM users WHERE id = %d", id))
	// ok: go-sqli-taint, go-sqli-sink
	db.Query(fmt.Sprintf("SELECT id, name FROM %s WHERE active = true", usersTable))
	// ok: go-sqli-taint, go-sqli-sink
	db.Exec("DELETE FROM " + auditTable + " WHERE created < now() - interval '90 days'")
}

func sqliGin(c *gin.Context) {
	// ruleid: go-sqli-taint
	db.Query("SELECT * FROM items WHERE sku = '" + c.Param("sku") + "'")
	// ok: go-sqli-taint
	db.Query("SELECT * FROM items WHERE sku = $1", c.Param("sku"))
	// ruleid: go-sqli-taint
	rows, err := FindUsersByName(c.Query("name"))
	if err != nil {
		return
	}
	defer rows.Close()
	name := c.Query("name")
	// ruleid: go-sqli-taint
	FindUsersByName(name)
	// ok: go-sqli-taint
	findUsersByEmail(c.Query("email"))
}

// Parameterised forms: a constant query in a variable with arguments, sqlx
// named parameters, and GORM conditions with placeholders.
func sqliParameterised(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := "SELECT name FROM users WHERE id = $1"
	// ok: go-sqli-taint
	db.QueryRow(query, id)
	args := []any{id}
	// ok: go-sqli-taint
	db.QueryRow(query, args...)
	// ok: go-sqli-taint
	sqlxDB.NamedExec("UPDATE users SET name = :name WHERE id = :id", map[string]any{"name": r.FormValue("name"), "id": id})
}

func sqliGorm(c *gin.Context) {
	name := c.Query("name")
	var found account
	// ok: go-sqli-taint
	gormDB.Where("name = ?", name).First(&found)
	// ruleid: go-sqli-taint
	gormDB.Where(fmt.Sprintf("name = '%s'", name)).First(&found)
	// ruleid: go-sqli-taint
	gormDB.Raw(c.Query("sql")).Scan(&found)
}

type account struct{ Name string }

// A prepared statement's QueryRow and Exec take arguments, not SQL.
func sqliPrepared(w http.ResponseWriter, r *http.Request) {
	stmt, err := db.Prepare("SELECT id FROM users WHERE name = ?")
	if err != nil {
		return
	}
	defer stmt.Close()
	// ok: go-sqli-taint
	stmt.QueryRow(r.URL.Query().Get("name"))
	// ok: go-sqli-taint
	checkLogin(r.FormValue("username"))
}

func checkLogin(username string) error {
	stmt, err := db.Prepare("SELECT id FROM users WHERE uname = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	// ok: go-sqli-sink
	return stmt.QueryRow(username).Err()
}

func FindUsersByName(name string) (*sql.Rows, error) {
	// ruleid: go-sqli-sink
	return db.Query(fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name))
}

// A wrapper that runs whatever query it is given builds nothing from its
// parameter; the caller decides what the SQL is.
func fetchRows(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	// ok: go-sqli-sink
	return db.QueryContext(ctx, query, args...)
}

// Not SQL: a policy query built with fmt.Sprintf.
func evaluatePolicy(rule string) {
	// ok: go-sqli-sink
	rego.Query(fmt.Sprintf("x = data.authz.%s", rule))
}

func DeleteSessions(owner string) error {
	query := "DELETE FROM sessions WHERE owner = '" + owner + "'"
	// ruleid: go-sqli-sink
	_, err := db.Exec(query)
	return err
}

// Unexported helpers are left to the taint rule, which follows a call into
// them within the file; a shape match on one proves nothing about its callers.
func truncateTable(name string) error {
	// ok: go-sqli-sink
	_, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE 1", name))
	return err
}

// A table or column name formatted into DDL is plumbing between internal
// callers, and no placeholder can stand in for it; the rule reports values.
func DropTable(table string) error {
	// ok: go-sqli-sink
	_, err := db.Exec(fmt.Sprintf("DROP TABLE `%s`", table))
	return err
}

func SyncIndex(table string, group int64) error {
	// ok: go-sqli-sink
	_, err := db.Exec(fmt.Sprintf("UPDATE %s SET max_index = max_index + 1 WHERE group_id = ?", table), group)
	return err
}

func FindByCategory(category string) (*sql.Rows, error) {
	// ruleid: go-sqli-sink
	return db.Query("SELECT * FROM product WHERE category='" + category + "'")
}

// The parameter is quoted before it is formatted in.
func RenameTable(name, old string) error {
	// ok: go-sqli-sink
	_, err := db.Exec(fmt.Sprintf("ALTER TABLE %s RENAME TO %s", quoteIdent(name), quoteIdent(old)))
	return err
}

func quoteIdent(name string) string { return `"` + name + `"` }

func findUsersByEmail(email string) (*sql.Rows, error) {
	// ok: go-sqli-sink
	return db.Query("SELECT id FROM users WHERE email = $1", email)
}

// --- Command injection ----------------------------------------------------------

func cmdiNetHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// ruleid: go-cmdi-taint
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ruleid: go-cmdi-taint
	exec.CommandContext(r.Context(), "/bin/bash", "-c", fmt.Sprintf("dig %s", host)).Run()
	// ruleid: go-cmdi-taint
	exec.Command(r.FormValue("tool"), "--version").Run()
	// ok: go-cmdi-taint
	exec.Command("ping", "-c", "1", host).Run()
	// ok: go-cmdi-taint, go-cmdi-sink
	exec.Command("sh", "-c", "df -h "+dataVolume).Run()
}

func cmdiGin(c *gin.Context) {
	// ruleid: go-cmdi-taint
	RunShell(c.Query("cmd"))
	// ok: go-cmdi-taint
	RunShell("uptime")
	cmd := c.Query("cmd")
	// ruleid: go-cmdi-taint
	RunShell(cmd)
	// ruleid: go-cmdi-taint
	runTool(c.Query("tool"), "--help")
}

func RunShell(script string) ([]byte, error) {
	// ruleid: go-cmdi-sink
	return exec.Command("/bin/sh", "-c", script).CombinedOutput()
}

func runTool(name string, args ...string) error {
	// ok: go-cmdi-sink
	return exec.Command(name, args...).Run()
}

// --- Server-side template injection ---------------------------------------------

func sstiNetHTTP(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("template")
	// ruleid: go-ssti-taint
	tmpl, err := template.New("preview").Parse(source)
	if err != nil {
		return
	}
	// ok: go-ssti-taint
	tmpl.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
	// ruleid: go-ssti-taint
	template.Must(template.New("note").Funcs(template.FuncMap{}).Parse(r.FormValue("note")))
	page := template.New("page")
	// ruleid: go-ssti-taint
	page.Parse(source)
	// ok: go-ssti-taint, go-ssti-sink
	welcome := template.Must(template.New("welcome").Parse(welcomeTemplate))
	// ok: go-ssti-taint
	welcome.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
}

func sstiIndirect(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("template")
	// ruleid: go-ssti-taint
	RenderPreview(source, r.URL.Query().Get("name"))
}

func sstiGin(c *gin.Context) {
	// ruleid: go-ssti-taint
	out, err := RenderPreview(c.Query("template"), c.Query("name"))
	if err != nil {
		return
	}
	c.String(http.StatusOK, out)
}

func RenderPreview(source, name string) (string, error) {
	// ruleid: go-ssti-sink
	tmpl, err := template.New("preview").Parse(source)
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	// ok: go-ssti-sink
	err = tmpl.Execute(&buf, map[string]string{"Name": name})
	return buf.String(), err
}
