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
	"slices"
	"strings"

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
