//go:build ignore

// Rule tests for rules/go-web.yaml: cross-site scripting, server-side request
// forgery, path traversal and open redirect in net/http and Gin handlers. See
// README.md.
package ruletests

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/microcosm-cc/bluemonday"

	"example.com/app/downloads"
	"example.com/app/httplib"
)

const statusPageTitle = "Inventory Service"

const (
	filesDir          = "/srv/app/files"
	upstreamStatusURL = "https://status.example.com/api/v2/status.json"
	dashboardPath     = "/account/dashboard"
)

var allowedFetchHosts = map[string]bool{"api.example.com": true}

var blockedFetchHosts = map[string]bool{"169.254.169.254": true}

var previewClient = &http.Client{}

// --- Cross-site scripting ---------------------------------------------------------

func xssNetHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// ruleid: go-xss-taint
	fmt.Fprintf(w, "<html><body><h1>Hello, %s</h1></body></html>", name)
	// ok: go-xss-taint
	fmt.Fprintf(w, "<html><body><h1>Hello, %s</h1></body></html>", html.EscapeString(name))
	// ruleid: go-xss-taint
	w.Write([]byte("<p>" + r.FormValue("message") + "</p>"))
	// ruleid: go-xss-taint
	io.WriteString(w, "<p>"+r.PostFormValue("bio")+"</p>")
	// ok: go-xss-taint, go-xss-sink
	fmt.Fprintf(w, "<h1>%s</h1>", statusPageTitle)
}

func xssGinIndirect(c *gin.Context) {
	name := c.Query("name")
	// ruleid: go-xss-taint
	WriteGreeting(c, name)
}

// html/template escapes what Execute writes; html.UnescapeString undoes
// escaping rather than doing it.
func xssHTMLTemplateExecute(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// ok: go-xss-taint
	greetingPage.Execute(w, map[string]string{"Name": r.URL.Query().Get("name")})
	// ruleid: go-xss-taint
	fmt.Fprintf(w, "<p>%s</p>", html.UnescapeString(r.FormValue("bio")))
}

func xssJSONResponse(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// ok: go-xss-taint
	fmt.Fprintf(w, `{"name": %q}`, r.URL.Query().Get("name"))
}

var greetingPage = template.Must(template.New("greeting").Parse(`<h1>Hello, {{.Name}}</h1>`))

func xssTemplateHTML(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: go-xss-taint
	greetingPage.Execute(w, map[string]any{"Name": template.HTML(name)})
	// ok: go-xss-taint
	greetingPage.Execute(w, map[string]any{"Name": name})
}

func xssGin(c *gin.Context) {
	// ruleid: go-xss-taint
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte("<p>"+c.Query("q")+"</p>"))
	// ok: go-xss-taint
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(c.Query("q")))
	// ruleid: go-xss-taint
	WriteGreeting(c, c.Query("name"))
}

func WriteGreeting(c *gin.Context, name string) {
	// ruleid: go-xss-sink
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf("<h1>Hello, %s</h1>", name)))
}

func writeBanner(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// ok: go-xss-sink
	fmt.Fprintf(w, "<div class=\"banner\">%s</div>", html.EscapeString(text))
}

// A helper that writes the HTML its caller rendered builds nothing from its
// parameter; one that sanitizes it first is safe.
func htmlResponse(w http.ResponseWriter, status int, page string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	// ok: go-xss-sink
	w.Write([]byte(page))
}

// Escaped, though not directly: the parameter only reaches the HTML through
// html.EscapeString.
func StylesheetLink(src string) template.HTML {
	// ok: go-xss-sink
	return template.HTML(`<link rel="stylesheet" href="` + html.EscapeString(assetURL(src)) + `">`)
}

func assetURL(src string) string { return "/assets/" + src }

func commentHTML(policy *bluemonday.Policy, comment string) template.HTML {
	// ok: go-xss-sink
	return template.HTML(policy.Sanitize("<div>" + comment + "</div>"))
}

// --- Server-side request forgery ------------------------------------------------

func ssrfNetHTTP(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: go-ssrf-taint
	http.Get(target)
	// ruleid: go-ssrf-taint
	previewClient.Post(target, "application/json", nil)
	// ruleid: go-ssrf-taint
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		return
	}
	previewClient.Do(req)
	// ok: go-ssrf-taint
	upload, err := http.NewRequest(http.MethodPost, upstreamStatusURL, r.Body)
	if err != nil {
		return
	}
	previewClient.Do(upload)
	// ok: go-ssrf-taint
	http.Get("https://api.example.com/users/" + r.URL.Query().Get("id"))
	// ok: go-ssrf-taint, go-ssrf-sink
	http.Get(upstreamStatusURL)
}

func ssrfAllowlisted(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || u.Scheme != "https" || !allowedFetchHosts[u.Hostname()] {
		http.Error(w, "url not allowed", http.StatusBadRequest)
		return
	}
	// ok: go-ssrf-taint
	http.Get(u.String())
}

// A denylist, or an allowlist check that only logs, guards nothing.
func ssrfDenylist(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil || blockedFetchHosts[u.Hostname()] {
		http.Error(w, "url not allowed", http.StatusBadRequest)
		return
	}
	// ruleid: go-ssrf-taint
	http.Get(u.String())
}

func ssrfAllowlistLogOnly(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(r.URL.Query().Get("url"))
	if err != nil {
		return
	}
	if !allowedFetchHosts[u.Hostname()] {
		log.Printf("fetching unlisted host %s", u.Hostname())
	}
	// ruleid: go-ssrf-taint
	http.Get(u.String())
}

// The check is on the parsed URL; the string it was parsed from is clean too.
func ssrfAllowlistRawString(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	u, err := url.Parse(target)
	if err != nil || !allowedFetchHosts[u.Host] {
		http.Error(w, "url not allowed", http.StatusBadRequest)
		return
	}
	// ok: go-ssrf-taint
	http.Get(target)
}

// A fixed scheme and host, built into a variable first.
func ssrfFixedHostVariable(w http.ResponseWriter, r *http.Request) {
	search := "https://api.example.com/search?q=" + url.QueryEscape(r.URL.Query().Get("q"))
	// ok: go-ssrf-taint
	http.Get(search)
	host := "https://" + r.URL.Query().Get("host") + "/status"
	// ruleid: go-ssrf-taint
	http.Get(host)
}

func ssrfGin(c *gin.Context) {
	// ruleid: go-ssrf-taint
	FetchRemote(c.Query("url"))
	target := c.Query("url")
	// ruleid: go-ssrf-taint
	FetchRemote(target)
}

func FetchRemote(target string) (*http.Response, error) {
	// ruleid: go-ssrf-sink
	return http.Get(target)
}

// A service client's request helper: the endpoint is built by its callers
// from configuration.
func rawRequest(ctx context.Context, method, endpoint string) (*http.Response, error) {
	// ok: go-ssrf-sink
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return previewClient.Do(req)
}

func fetchAllowed(target string) (*http.Response, error) {
	u, err := url.Parse(target)
	if err != nil || !allowedFetchHosts[u.Hostname()] {
		return nil, err
	}
	// ok: go-ssrf-sink
	return http.Get(u.String())
}

// A denylist does not make a helper safe to call with request input.
func ssrfDenylistHelper(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-ssrf-taint
	fetchUnlessBlocked(r.URL.Query().Get("url"))
}

func fetchUnlessBlocked(target string) (*http.Response, error) {
	u, err := url.Parse(target)
	if err != nil || blockedFetchHosts[u.Hostname()] {
		return nil, err
	}
	return http.Get(target)
}

func FetchUnlessBlocked(target string) (*http.Response, error) {
	u, err := url.Parse(target)
	if err != nil || blockedFetchHosts[u.Hostname()] {
		return nil, err
	}
	// ruleid: go-ssrf-sink
	return http.Get(target)
}

// --- Path traversal -------------------------------------------------------------

func pathNetHTTP(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: go-path-traversal-taint
	os.ReadFile(filepath.Join(filesDir, name))
	// ruleid: go-path-traversal-taint
	http.ServeFile(w, r, filepath.Join(filesDir, name))
	// ok: go-path-traversal-taint
	os.ReadFile(filepath.Join(filesDir, filepath.Base(name)))
	// ok: go-path-traversal-taint, go-path-traversal-sink
	os.ReadFile(filepath.Join(filesDir, "terms-of-service.txt"))
}

func pathContained(w http.ResponseWriter, r *http.Request) {
	base, err := filepath.Abs(filesDir)
	if err != nil {
		return
	}
	target, err := filepath.Abs(filepath.Join(base, r.URL.Query().Get("file")))
	if err != nil || !strings.HasPrefix(target, base+string(os.PathSeparator)) {
		http.Error(w, "invalid file", http.StatusBadRequest)
		return
	}
	// ok: go-path-traversal-taint
	os.ReadFile(target)
}

// filepath.Clean, then a separator-terminated prefix check that exits.
func pathCleanContained(w http.ResponseWriter, r *http.Request) {
	p := filepath.Clean(filepath.Join(filesDir, r.URL.Query().Get("file")))
	if !strings.HasPrefix(p, filesDir+string(os.PathSeparator)) {
		http.Error(w, "invalid file", http.StatusBadRequest)
		return
	}
	// ok: go-path-traversal-taint
	os.ReadFile(p)
}

// The same check without an exit guards nothing.
func pathPrefixNoExit(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(filesDir, r.URL.Query().Get("file"))
	if !strings.HasPrefix(p, filesDir+string(os.PathSeparator)) {
		log.Printf("outside the files directory: %s", p)
	}
	// ruleid: go-path-traversal-taint
	os.ReadFile(p)
}

// filepath.Rel, then a check that the relative path does not climb out.
func pathRelContained(w http.ResponseWriter, r *http.Request) {
	p := filepath.Join(filesDir, r.URL.Query().Get("file"))
	rel, err := filepath.Rel(filesDir, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		http.Error(w, "invalid file", http.StatusBadRequest)
		return
	}
	// ok: go-path-traversal-taint
	os.ReadFile(p)
}

// http.ServeFile rejects ".." in the request's URL path, not in the file
// system path it is handed.
func pathServeFileJoined(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-path-traversal-taint
	http.ServeFile(w, r, filepath.Join(filesDir, r.FormValue("file")))
}

// A prefix check without a trailing separator is not containment: it lets
// /srv/app/files_evil/x through.
func pathPrefixWithoutSeparator(w http.ResponseWriter, r *http.Request) {
	target := filepath.Join(filesDir, r.URL.Query().Get("file"))
	if !strings.HasPrefix(target, filesDir) {
		http.Error(w, "invalid file", http.StatusBadRequest)
		return
	}
	// ruleid: go-path-traversal-taint
	os.ReadFile(target)
}

func pathGin(c *gin.Context) {
	// ruleid: go-path-traversal-taint
	c.File(filepath.Join(filesDir, c.Query("file")))
	// ruleid: go-path-traversal-taint
	ReadStoredFile(c.Param("name"))
	name := c.Param("name")
	// ruleid: go-path-traversal-taint
	ReadStoredFile(name)
}

// The request input goes to the parameter that does not reach the sink.
func copyUpload(w http.ResponseWriter, r *http.Request) {
	// ok: go-path-traversal-taint
	copyFile(r.FormValue("name"), "/srv/app/incoming/upload.bin")
	// ruleid: go-path-traversal-taint
	copyFile("upload.bin", r.FormValue("source"))
	// ok: go-path-traversal-taint
	ReadStoredFile(filepath.Base(r.FormValue("name")))
	// A bare call cannot name a method: this readDocument is a function of
	// another file, not the method below.
	// ok: go-path-traversal-taint
	readDocument(r.FormValue("name"))
}

func copyFile(label, src string) error {
	log.Printf("copying %s", label)
	_, err := os.Open(src)
	return err
}

type docStore struct{}

func (s docStore) readDocument(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(filesDir, name))
}

func ReadStoredFile(name string) ([]byte, error) {
	// ruleid: go-path-traversal-sink
	return os.ReadFile(filepath.Join(filesDir, name))
}

// Numbers formatted into a path carry no separators.
func deleteArchives(w http.ResponseWriter, r *http.Request) {
	ids := []int{}
	if err := json.NewDecoder(r.Body).Decode(&ids); err != nil {
		return
	}
	for _, id := range ids {
		// ok: go-path-traversal-taint
		os.Remove(filepath.Join(filesDir, "archive", strconv.Itoa(id)))
	}
	upload := r.FormValue("upload")
	// ok: go-path-traversal-taint
	os.Create(filepath.Join(filesDir, uuidString()+filepath.Ext(upload)))
}

func uuidString() string { return "00000000-0000-0000-0000-000000000000" }

// A value another package looks up by request input is not request input:
// the file name here comes from the server's own records. (A function of
// this file is different: the rule follows calls into those, so its result
// keeps the taint.)
func downloadByID(c *gin.Context) {
	record, err := downloads.Find(c.Param("id"))
	if err != nil {
		return
	}
	// ok: go-path-traversal-taint
	c.FileAttachment(record.Path, filepath.Base(record.Path))
	cached, ok := thumbCache[c.Query("size")]
	if !ok {
		return
	}
	// ok: go-path-traversal-taint
	c.File(cached)
}

// The same inside a handler registered as a function literal.
func registerDownloads(router *gin.RouterGroup) {
	router.GET("/dl/:id", func(c *gin.Context) {
		record, err := downloads.Find(c.Param("id"))
		if err != nil {
			return
		}
		// ok: go-path-traversal-taint
		c.File(record.Path)
		// ruleid: go-path-traversal-taint
		c.File(filepath.Join(filesDir, c.Param("id")))
	})
}

var thumbCache = map[string]string{}

// The parameter is the directory; what is joined onto it is fixed.
func readModulePath(root string) ([]byte, error) {
	// ok: go-path-traversal-sink
	return os.ReadFile(filepath.Join(root, "go.mod"))
}

// The upload name is checked to be a bare file name first.
func uploadChunk(c *gin.Context) {
	filename := c.PostForm("filename")
	if filename == "" || filepath.Base(filename) != filename || strings.ContainsAny(filename, `/\`) {
		c.Status(http.StatusBadRequest)
		return
	}
	// ok: go-path-traversal-taint
	os.Create(filepath.Join(filesDir, filename))
}

// A handler built inside another call: the value it looks up is still not
// request input.
func newPreviewServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record, err := downloads.Find(r.URL.Query().Get("id"))
		if err != nil {
			return
		}
		// ok: go-path-traversal-taint
		http.ServeFile(w, r, record.Path)
	}))
}

// A query-escaped value has no separators left.
func fixtureFile(w http.ResponseWriter, r *http.Request) {
	// ok: go-path-traversal-taint
	os.Create(filepath.Join(filesDir, r.Method+"_"+url.QueryEscape(r.URL.RawQuery)))
}

// A ".." check that only logs does not make a helper safe.
func pathLoggedHelper(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-path-traversal-taint
	readLogged(r.URL.Query().Get("file"))
}

func readLogged(name string) ([]byte, error) {
	if strings.Contains(name, "..") {
		log.Printf("suspicious file name %q", name)
	}
	return os.ReadFile(filepath.Join(filesDir, name))
}

func readPublicFile(name string) ([]byte, error) {
	// ok: go-path-traversal-sink
	return os.ReadFile(filepath.Join(filesDir, filepath.Base(name)))
}

// --- Open redirect --------------------------------------------------------------

func redirectNetHTTP(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	// ruleid: go-open-redirect-taint
	http.Redirect(w, r, next, http.StatusFound)
	// ruleid: go-open-redirect-taint
	w.Header().Set("Location", next)
	// ok: go-open-redirect-taint
	http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusFound)
	// ok: go-open-redirect-taint, go-open-redirect-sink
	http.Redirect(w, r, dashboardPath, http.StatusFound)
}

func redirectLocalOnly(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/"
	}
	// ok: go-open-redirect-taint
	http.Redirect(w, r, next, http.StatusFound)
}

// A check function on the target, qualified by its package and taking the
// target among other arguments.
func redirectChecked(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("redirect")
	if r.Method != http.MethodPost || !httplib.IsCurrentSiteURL(r.Context(), next) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// ok: go-open-redirect-taint
	w.Header().Set("Location", next)
	// ok: go-open-redirect-taint
	http.Redirect(w, r, "?"+r.URL.RawQuery, http.StatusSeeOther)
}

// "//" alone is not a local-path guard: https://evil.com passes it.
func redirectSlashSlashOnly(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if strings.HasPrefix(next, "//") {
		next = "/"
	}
	// ruleid: go-open-redirect-taint
	http.Redirect(w, r, next, http.StatusFound)
}

// A full local-path check that neither exits nor replaces the target.
func redirectCheckNoExit(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		log.Printf("external redirect to %s", next)
	}
	// ruleid: go-open-redirect-taint
	http.Redirect(w, r, next, http.StatusFound)
}

func redirectLocalReturn(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if strings.HasPrefix(next, "//") || !strings.HasPrefix(next, "/") {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	// ok: go-open-redirect-taint
	http.Redirect(w, r, next, http.StatusFound)
}

// The two checks anywhere in an || chain, the replacement nested in an if.
func redirectLoginTarget(w http.ResponseWriter, r *http.Request, singleUser bool) {
	next := r.FormValue("to")
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		if singleUser {
			next = "/me/new"
		} else {
			next = "/"
		}
	}
	// ok: go-open-redirect-taint
	w.Header().Set("Location", next)
}

// A fixed local path built into a variable first.
func redirectFixedPathVariable(w http.ResponseWriter, r *http.Request) {
	target := "/settings/" + r.URL.Query().Get("tab")
	// ok: go-open-redirect-taint
	http.Redirect(w, r, target, http.StatusFound)
}

func redirectIsLocal(c *gin.Context) {
	target := c.Query("next")
	isLocal := strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//")
	if !isLocal {
		target = "/"
	}
	// ok: go-open-redirect-taint
	c.Redirect(http.StatusFound, target)
}

func redirectGin(c *gin.Context) {
	// ruleid: go-open-redirect-taint
	c.Redirect(http.StatusFound, c.Query("next"))
	// ruleid: go-open-redirect-taint
	c.Header("Location", c.Query("next"))
	// ruleid: go-open-redirect-taint
	RedirectTo(c, c.Query("next"))
	next := c.Query("next")
	// ruleid: go-open-redirect-taint
	RedirectTo(c, next)
}

func RedirectTo(c *gin.Context, target string) {
	// ruleid: go-open-redirect-sink
	c.Redirect(http.StatusFound, target)
}

// A // check alone does not make a helper safe to call with request input.
func redirectSlashSlashHelper(w http.ResponseWriter, r *http.Request) {
	// ruleid: go-open-redirect-taint
	redirectNotSchemeRelative(w, r, r.URL.Query().Get("next"))
}

func redirectNotSchemeRelative(w http.ResponseWriter, r *http.Request, target string) {
	if strings.HasPrefix(target, "//") {
		target = "/"
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func RedirectNotSchemeRelative(w http.ResponseWriter, r *http.Request, target string) {
	if strings.HasPrefix(target, "//") {
		target = "/"
	}
	// ruleid: go-open-redirect-sink
	http.Redirect(w, r, target, http.StatusFound)
}

func RedirectLocal(w http.ResponseWriter, r *http.Request, target string) {
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") {
		target = "/"
	}
	// ok: go-open-redirect-sink
	http.Redirect(w, r, target, http.StatusFound)
}

func redirectToSection(w http.ResponseWriter, r *http.Request, section string) {
	// ok: go-open-redirect-sink
	http.Redirect(w, r, "/help#"+url.PathEscape(section), http.StatusFound)
}

// --- Same-file helpers that hand their input back --------------------------------

var scriptTag = regexp.MustCompile(`<script[^>]*>.*</script>`)

// Hands back a filtered copy of its input, through a variable.
func stripScripts(text string) string {
	output := scriptTag.ReplaceAllString(text, "")
	return output
}

func xssFilteredHelper(w http.ResponseWriter, r *http.Request) {
	term := stripScripts(r.FormValue("term"))
	// ruleid: go-xss-taint
	greetingPage.Execute(w, map[string]any{"Name": template.HTML(term)})
}

func xssFilteredInline(w http.ResponseWriter, r *http.Request) {
	term := scriptTag.ReplaceAllString(r.FormValue("term"), "")
	// ruleid: go-xss-taint
	greetingPage.Execute(w, map[string]any{"Name": template.HTML(term)})
}
