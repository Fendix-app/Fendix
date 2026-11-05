//go:build ignore

// Rule tests for rules/go-web.yaml: the guard shapes. A guard counts only when
// its check is the whole condition or one disjunct of an || chain (one
// conjunct of an && chain for a positive if), and its exit (a return, or a
// literal replacing a redirect target) is the last statement of the block.
// See go-web.go and README.md.
package ruletests

import (
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
)

const guardBase = "/srv/app/files"

var (
	guardAllowed = map[string]bool{"api.example.com": true}
	guardHosts   = []string{"api.example.com"}
	verbose      bool
	strict       bool
	debugMode    bool
)

// --- SSRF host allowlists ------------------------------------------------------

func ssrfSchemeAndHost(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.URL.Query().Get("url"))
	if u.Scheme == "https" && !guardAllowed[u.Host] {
		return
	}
	// ruleid: go-ssrf-taint
	http.Get(u.String())
}

func ssrfExitNested(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.URL.Query().Get("url"))
	if !guardAllowed[u.Host] {
		if verbose {
			return
		}
		log.Println("unlisted")
	}
	// ruleid: go-ssrf-taint
	http.Get(u.String())
}

func ssrfExitInClosure(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.URL.Query().Get("url"))
	if !guardAllowed[u.Host] {
		func() {
			log.Println("unlisted")
			return
		}()
	}
	// ruleid: go-ssrf-taint
	http.Get(u.String())
}

func ssrfExitInGoroutine(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.URL.Query().Get("url"))
	if !guardAllowed[u.Host] {
		go func() {
			return
		}()
	}
	// ruleid: go-ssrf-taint
	http.Get(u.String())
}

func ssrfExitInLoop(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.URL.Query().Get("url"))
	if !guardAllowed[u.Host] {
		for i := 0; i < 1; i++ {
			return
		}
	}
	// ruleid: go-ssrf-taint
	http.Get(u.String())
}

func ssrfElseOfAllowlist(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.URL.Query().Get("url"))
	if guardAllowed[u.Host] {
		log.Println("listed")
	} else {
		// ruleid: go-ssrf-taint
		http.Get(u.String())
	}
}

// A substring check on the host is not an allowlist: evil-example.com.attacker
// passes it.
func ssrfSubstringHost(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.URL.Query().Get("url"))
	if !strings.Contains(u.Host, "example.com") {
		return
	}
	// ruleid: go-ssrf-taint
	http.Get(u.String())
}

func ssrfAllowlistSlice(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || !slices.Contains(guardHosts, u.Hostname()) {
		http.Error(w, "url not allowed", http.StatusBadRequest)
		return
	}
	// ok: go-ssrf-taint
	http.Get(u.String())
}

func ssrfAllowlistPositive(w http.ResponseWriter, r *http.Request) {
	u, _ := url.Parse(r.URL.Query().Get("url"))
	if guardAllowed[u.Host] && u.Scheme == "https" {
		// ok: go-ssrf-taint
		http.Get(u.String())
	}
}

// Request input after a "?" lands in the query string: the base decides
// where the request goes.
var statusBase = "http://localhost:8080/api"

func ssrfQueryAfterBase(w http.ResponseWriter, r *http.Request) {
	// ok: go-ssrf-taint
	http.Get(statusBase + "?input=" + url.QueryEscape(r.URL.Query().Get("q")))
	target := statusBase + "?input=" + r.URL.Query().Get("q")
	// ok: go-ssrf-taint
	http.Get(target)
	// ruleid: go-ssrf-taint
	http.Get(r.URL.Query().Get("base") + "?input=x")
}

// --- Open redirect local-path guards -------------------------------------------

func redirectSlashUnderAnd(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	if (!strings.HasPrefix(u, "/") && strict) || strings.HasPrefix(u, "//") {
		return
	}
	// ruleid: go-open-redirect-taint
	http.Redirect(w, r, u, http.StatusFound)
}

func redirectChecksConjoined(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	if !strings.HasPrefix(u, "/") && strings.HasPrefix(u, "//") {
		return
	}
	// ruleid: go-open-redirect-taint
	http.Redirect(w, r, u, http.StatusFound)
}

func redirectNegatedLocal(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	if !(strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//")) {
		// ruleid: go-open-redirect-taint
		http.Redirect(w, r, u, http.StatusFound)
		return
	}
}

func redirectElseOfLocal(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	if strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//") {
		log.Println("local")
	} else {
		// ruleid: go-open-redirect-taint
		http.Redirect(w, r, u, http.StatusFound)
	}
}

func redirectLocalWithOr(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	ok := strings.HasPrefix(u, "/") || !strings.HasPrefix(u, "//")
	if !ok {
		return
	}
	// ruleid: go-open-redirect-taint
	http.Redirect(w, r, u, http.StatusFound)
}

func redirectExitNested(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	if !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") {
		if debugMode {
			return
		}
		log.Println("external")
	}
	// ruleid: go-open-redirect-taint
	http.Redirect(w, r, u, http.StatusFound)
}

func isLocalTarget(s string) bool { return strings.HasPrefix(s, "/") && !strings.HasPrefix(s, "//") }

func redirectWhenNotLocal(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	if !isLocalTarget(u) {
		// ruleid: go-open-redirect-taint
		http.Redirect(w, r, u, http.StatusFound)
	}
}

func redirectWhenLocal(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	if isLocalTarget(u) {
		// ok: go-open-redirect-taint
		http.Redirect(w, r, u, http.StatusFound)
	}
}

func hasLocalePrefix(s string) bool { return strings.HasPrefix(s, "/en") }

func redirectLocalePrefix(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	if hasLocalePrefix(u) {
		// ruleid: go-open-redirect-taint
		http.Redirect(w, r, u, http.StatusFound)
	}
}

func redirectReplaceInGoroutine(w http.ResponseWriter, r *http.Request) {
	u := r.URL.Query().Get("next")
	if !strings.HasPrefix(u, "/") || strings.HasPrefix(u, "//") {
		go func() {
			u = "/"
		}()
	}
	// ruleid: go-open-redirect-taint
	http.Redirect(w, r, u, http.StatusFound)
}

func redirectLoggedHelperCall(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-open-redirect-taint
	redirectLogged(w, r, r.URL.Query().Get("next"))
}

func redirectLogged(w http.ResponseWriter, r *http.Request, target string) {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		log.Printf("external redirect to %s", target)
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func redirectParsedHostLogged(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-open-redirect-taint
	redirectAbsLogged(w, r, r.URL.Query().Get("next"))
}

func redirectAbsLogged(w http.ResponseWriter, r *http.Request, target string) {
	if p, err := url.Parse(target); err != nil || p.IsAbs() || p.Host != "" {
		log.Printf("absolute redirect to %s", target)
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func redirectGuardedHelperCall(w http.ResponseWriter, r *http.Request) {
	// ok: go-open-redirect-taint
	redirectGuarded(w, r, r.URL.Query().Get("next"))
}

func redirectGuarded(w http.ResponseWriter, r *http.Request, target string) {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func redirectPathWithQuery(w http.ResponseWriter, r *http.Request) {
	// ok: go-open-redirect-taint
	http.Redirect(w, r, r.URL.Path+"?"+r.URL.Query().Encode(), http.StatusFound)
}

// --- Path traversal containment ------------------------------------------------

// Since Go 1.17 mime/multipart keeps only the base name of an upload's file
// name, so FileHeader.Filename carries no separator.
func uploadGin(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		return
	}
	// ok: go-path-traversal-taint
	c.SaveUploadedFile(file, filepath.Join("uploads", file.Filename))
}

func uploadNetHTTP(w http.ResponseWriter, r *http.Request) {
	_, header, err := r.FormFile("file")
	if err != nil {
		return
	}
	// ok: go-path-traversal-taint
	os.Create(filepath.Join("uploads", header.Filename))
}

// A ".." check does not stop an absolute path opened as is.
func pathDotDotThenRaw(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	if strings.Contains(name, "..") {
		return
	}
	// ruleid: go-path-traversal-taint
	os.ReadFile(name)
	// ok: go-path-traversal-taint
	os.ReadFile(filepath.Join(guardBase, name))
}

func pathContainmentUnderAnd(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(guardBase, r.URL.Query().Get("f"))
	if debugMode && !strings.HasPrefix(p, guardBase+"/") {
		return
	}
	// ruleid: go-path-traversal-taint
	os.ReadFile(p)
}

func pathExitNested(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(guardBase, r.URL.Query().Get("f"))
	if !strings.HasPrefix(p, guardBase+"/") {
		if debugMode {
			return
		}
		log.Println("outside")
	}
	// ruleid: go-path-traversal-taint
	os.ReadFile(p)
}

func pathElseOfContained(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(guardBase, r.URL.Query().Get("f"))
	if strings.HasPrefix(p, guardBase+"/") {
		log.Println("inside")
	} else {
		// ruleid: go-path-traversal-taint
		os.ReadFile(p)
	}
}

func pathContainedPositive(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(guardBase, r.URL.Query().Get("f"))
	if strings.HasPrefix(p, guardBase+"/") {
		// ok: go-path-traversal-taint
		os.ReadFile(p)
	}
}

// filepath.Clean("/"+x) drops "..", but the result is still an absolute path
// unless it is joined onto a base.
func pathCleanRooted(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-path-traversal-taint
	os.ReadFile(filepath.Clean("/" + r.URL.Query().Get("f")))
	// ok: go-path-traversal-taint
	os.ReadFile(filepath.Join(guardBase, filepath.Clean("/"+r.URL.Query().Get("f"))))
}

func pathRelUnderAnd(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(guardBase, r.URL.Query().Get("f"))
	rel, err := filepath.Rel(guardBase, p)
	if err == nil && strings.HasPrefix(rel, "..") && debugMode {
		return
	}
	// ruleid: go-path-traversal-taint
	os.ReadFile(p)
}

func pathLoggedJoinHelperCall(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-path-traversal-taint
	readAfterLoggedCheck(r.URL.Query().Get("f"))
}

func readAfterLoggedCheck(name string) ([]byte, error) {
	if strings.Contains(name, "..") {
		if debugMode {
			return nil, nil
		}
		log.Println("dot-dot")
	}
	return os.ReadFile(filepath.Join(guardBase, name))
}
