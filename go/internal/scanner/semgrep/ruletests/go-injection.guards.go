//go:build ignore

// Rule tests for rules/go-injection.yaml: SQL identifiers chosen from an
// allowlist, same-file helpers that do not hand their input back, the
// builtins len, cap and make, and GORM conditions. See go-injection.go and
// README.md.
package ruletests

import (
	"cmp"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"slices"
	"strings"
	"text/template"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var guardDB *sql.DB

var guardGorm *gorm.DB

var sortColumns = map[string]string{"name": "name", "date": "created_at"}

var allowedSort = map[string]bool{"name": true, "created_at": true}

var verboseSQL bool

// --- Same-file helpers ---------------------------------------------------------

// Returns a column from a fixed map, never its input.
func sortColumn(key string) string {
	if col, ok := sortColumns[key]; ok {
		return col
	}
	return "id"
}

func direction(d string) string {
	switch d {
	case "desc":
		return "DESC"
	default:
		return "ASC"
	}
}

func lookupID(name string) string { return "42" }

// Hands its input back.
func trimmed(s string) string { return strings.TrimSpace(s) }

func sqliHelpers(w http.ResponseWriter, r *http.Request) {
	col := sortColumn(r.URL.Query().Get("sort"))
	// ok: go-sqli-taint
	guardDB.Query("SELECT id, name FROM users ORDER BY " + col)
	// ok: go-sqli-taint
	guardDB.Query(fmt.Sprintf("SELECT * FROM users ORDER BY name %s", direction(r.URL.Query().Get("dir"))))
	id := lookupID(r.URL.Query().Get("name"))
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM t WHERE id = " + id)
	name := trimmed(r.URL.Query().Get("name"))
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM users WHERE name = '" + name + "'")
}

// --- Constant helpers: the body is in this file and every return is constant --------

// Map lookups in other shapes.
func sortColumnTwoStep(key string) string {
	col, ok := sortColumns[key]
	if !ok {
		return "id"
	}
	return col
}

func sortColumnNonEmpty(key string) string {
	if col := sortColumns[key]; col != "" {
		return col
	}
	return "id"
}

func sortColumnDirect(key string) string {
	return sortColumns[key]
}

// Literals only, through a branch.
func tableFor(kind string) string {
	if kind == "audit" {
		return "audit_log"
	}
	return "users"
}

// A map whose value is built at run time is not a lookup of constants.
var dynamicColumns = map[string]string{"name": "name", "mine": "owner_" + guardSuffix}

var guardSuffix string

func dynamicColumn(key string) string {
	if col, ok := dynamicColumns[key]; ok {
		return col
	}
	return "id"
}

// Returns its input for a known value, so it is not a constant.
func validatedSort(s string) string {
	if allowedSort[s] {
		return s
	}
	return "id"
}

// A switch with one branch that hands the input back.
func directionOrInput(d string) string {
	switch d {
	case "desc":
		return "DESC"
	case "asc":
		return "ASC"
	default:
		return d
	}
}

// The map is declared in the function.
func sortColumnLocal(key string) string {
	columns := map[string]string{"name": "name", "date": "created_at"}
	if col, ok := columns[key]; ok {
		return col
	}
	return "id"
}

func sortColumnLocalDynamic(key string) string {
	columns := map[string]string{"name": "name", "mine": "owner_" + guardSuffix}
	if col, ok := columns[key]; ok {
		return col
	}
	return "id"
}

type guardServer struct{}

// Methods of this file follow the same rule as functions.
func (s *guardServer) column(key string) string {
	if col, ok := sortColumns[key]; ok {
		return col
	}
	return "id"
}

func (s *guardServer) literal(key string) string { return "users" }

func (s *guardServer) build(key string) string {
	return "SELECT * FROM users WHERE name = '" + key + "'"
}

func (s *guardServer) handle(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("sort")
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + s.column(key))
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM " + s.literal(key))
	// ruleid: go-sqli-taint
	guardDB.Query(s.build(key))
}

// A switch of any size, with a statement before it and comments inside: every
// return is a literal, and the word "return" in a comment or a string is not
// a return.
func columnFor(kind string) string {
	kind = strings.ToLower(kind)
	switch kind {
	case "a", "b", "c":
		// return the name column
		return "name"
	case "d":
		return "date"
	case "e":
		return "e_col"
	case "f":
		return "f_col"
	case "g":
		return "g_col"
	case "h":
		return "h_col"
	case "i":
		return "return"
	case "j":
		return "j_col"
	case "k":
		return "k_col"
	case "l":
		return "l_col"
	default:
		return "id"
	}
}

// A return of a concatenation is not a literal.
func suffixedColumn(kind string) string {
	switch kind {
	case "a":
		return "col_" + kind
	}
	return "id"
}

func constantHelpers(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("sort")
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sortColumnTwoStep(key))
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sortColumnNonEmpty(key))
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sortColumnDirect(key))
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM " + tableFor(key))
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + columnFor(key))
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + suffixedColumn(key))
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sortColumnLocal(key))
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sortColumnLocalDynamic(key))
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + dynamicColumn(key))
	// A validate-then-return-input helper is a pass-through to this rule (a
	// known false positive, see docs/semgrep-rules.md).
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + validatedSort(key))
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY name " + directionOrInput(key))
}

// --- Unknown calls keep the input's taint --------------------------------------------

type searchFilter struct{ Name string }

func structQuery(f searchFilter) string {
	return "SELECT * FROM t WHERE name = '" + f.Name + "'"
}

func chainedQuery(s string) string {
	a := "SELECT * FROM t WHERE name = '" + s + "'"
	b := strings.TrimSpace(a)
	return b
}

func branchedQuery(s string) string {
	var q string
	if s != "" {
		q = "SELECT * FROM t WHERE name = '" + s + "'"
	}
	return q
}

func builderQuery(s string) string {
	var sb strings.Builder
	sb.WriteString("SELECT * FROM t WHERE name = '")
	sb.WriteString(s)
	sb.WriteString("'")
	return sb.String()
}

func tupleQuery(s string) (string, []interface{}) {
	return "SELECT * FROM t WHERE name = '" + s + "'", nil
}

type queryBuilder struct{}

func (queryBuilder) build(s string) string { return "SELECT * FROM t WHERE name = '" + s + "'" }

func unknownCalls(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	// A function of another file of the package.
	// ruleid: go-sqli-taint
	guardDB.Query(otherFileQuery(q))
	f := searchFilter{Name: q}
	// ruleid: go-sqli-taint
	guardDB.Query(structQuery(f))
	// ruleid: go-sqli-taint
	guardDB.Query(chainedQuery(q))
	// ruleid: go-sqli-taint
	guardDB.Query(branchedQuery(q))
	// ruleid: go-sqli-taint
	guardDB.Query(builderQuery(q))
	// ruleid: go-sqli-taint
	guardDB.Query(tupleQuery(q))
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM t WHERE name = '" + sanitize(q) + "'")
	// ruleid: go-sqli-taint
	guardDB.Query(queryBuilder{}.build(q))
	// A package-qualified call is a lookup, whatever it is called: its result
	// is not request input (see the pack header and docs/semgrep-rules.md).
	// ok: go-sqli-taint
	guardDB.Query(otherpkg.Build(q))
}

func unknownCallsGin(c *gin.Context) {
	f := searchFilter{Name: c.Query("q")}
	// ruleid: go-sqli-taint
	guardDB.Query(structQuery(f))
	// ruleid: go-sqli-taint
	guardDB.Query(otherFileQuery(c.Param("id")))
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM t WHERE name = '" + sanitize(c.Query("q")) + "'")
}

// --- Identifier allowlists ------------------------------------------------------

func sortAllowlistExit(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	if !allowedSort[sort] {
		http.Error(w, "bad sort", http.StatusBadRequest)
		return
	}
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sort)
}

func sortAllowlistReplace(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	if !slices.Contains([]string{"asc", "desc"}, dir) {
		dir = "asc"
	}
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY name " + dir)
}

func sortSwitchDefault(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	switch dir {
	case "asc", "desc":
	default:
		dir = "asc"
	}
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY name " + dir)
}

func sortComparisons(c *gin.Context) {
	order := c.DefaultQuery("order", "asc")
	if order != "asc" && order != "desc" {
		order = "asc"
	}
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY name " + order)
}

// The comma-ok membership test, for a set and for a bool map.
var allowedColumns = map[string]struct{}{"name": {}, "created_at": {}}

func sortCommaOkReplace(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	if _, ok := allowedColumns[sort]; !ok {
		sort = "name"
	}
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sort)
}

func sortCommaOkExit(c *gin.Context) {
	sort := c.Query("sort")
	if _, ok := allowedSort[sort]; !ok {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sort)
}

func sortCommaOkTwoStatements(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	_, ok := allowedColumns[sort]
	if !ok {
		http.Error(w, "bad sort", http.StatusBadRequest)
		return
	}
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sort)
}

// The check must be the whole condition, and the exit direct.
func sortCommaOkUnderAnd(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	if _, ok := allowedSort[sort]; !ok && strict {
		return
	}
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sort)
}

func sortCommaOkLogged(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	if _, ok := allowedSort[sort]; !ok {
		log.Printf("unexpected sort %q", sort)
	}
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sort)
}

// An allowlist check that only logs guards nothing.
func sortAllowlistLogged(w http.ResponseWriter, r *http.Request) {
	sort := r.URL.Query().Get("sort")
	if !allowedSort[sort] {
		if verboseSQL {
			return
		}
		log.Printf("unexpected sort %q", sort)
	}
	// ruleid: go-sqli-taint
	guardDB.Query("SELECT * FROM users ORDER BY " + sort)
}

// --- Builtins and placeholder lists ---------------------------------------------

func sqliInPlaceholders(c *gin.Context) {
	ids := c.QueryArray("id")
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	// ok: go-sqli-taint
	guardDB.Query(fmt.Sprintf("SELECT * FROM t WHERE id IN (%s)", placeholders), args...)
	n := len(c.Query("q"))
	// ok: go-sqli-taint
	guardDB.Query(fmt.Sprintf("SELECT * FROM t LIMIT %d", n))
}

func sqliNumberedPlaceholders(w http.ResponseWriter, r *http.Request) {
	ids := r.URL.Query()["id"]
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i := range ids {
		ph[i] = fmt.Sprintf("$%d", i+1)
		args[i] = ids[i]
	}
	// ok: go-sqli-taint
	guardDB.Query("SELECT * FROM t WHERE id IN ("+strings.Join(ph, ",")+")", args...)
}

// --- GORM conditions -------------------------------------------------------------

func gormRawConditions(c *gin.Context) {
	// ruleid: go-sqli-taint
	guardGorm.Where(c.Query("filter"))
	cond := fmt.Sprintf("name = '%s'", c.Query("name"))
	// ruleid: go-sqli-taint
	guardGorm.Where(cond)
	// ruleid: go-sqli-taint
	guardGorm.Order(c.Query("sort"))
	sort := c.Query("sort")
	// ruleid: go-sqli-taint
	guardGorm.Order(sort)
	// ok: go-sqli-taint
	guardGorm.Where("name = ?", c.Query("name"))
	// ok: go-sqli-taint
	guardGorm.Where(map[string]any{"name": c.Query("name")})
	var filter account
	if err := c.ShouldBindJSON(&filter); err != nil {
		return
	}
	// ok: go-sqli-taint
	guardGorm.Where(&filter)
}

// cmp.Or picks its first non-empty argument; it is not GORM's Or.
func firstNonEmpty(w http.ResponseWriter, r *http.Request) {
	// ok: go-sqli-taint
	id := cmp.Or(r.URL.Query().Get("error"), r.URL.Query().Get("id"))
	_ = id
}

func firstNonEmptyGin(c *gin.Context) {
	// ok: go-sqli-taint
	order := cmp.Or(c.Query("order"), "asc")
	_ = order
}

// --- The same rule for the other injection classes ---------------------------------

func toolFlag(kind string) string {
	switch kind {
	case "quiet":
		return "-q"
	default:
		return "-v"
	}
}

func unknownCallsCommands(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// ok: go-cmdi-taint
	exec.Command("sh", "-c", "ping "+toolFlag(host)).Run()
	// ruleid: go-cmdi-taint
	exec.Command("sh", "-c", "ping "+otherFileHost(host)).Run()
	// ruleid: go-cmdi-taint
	exec.Command("sh", "-c", "ping "+withFlag(host)).Run()
}

func withFlag(host string) string {
	flags := strings.TrimSpace(host)
	return flags
}

func unknownCallsTemplates(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("tpl")
	// ok: go-ssti-taint
	template.New("a").Parse(toolFlag(source))
	// ruleid: go-ssti-taint
	template.New("a").Parse(otherFileTemplate(source))
	// ruleid: go-ssti-taint
	template.New("a").Parse(withFlag(source))
}
