package verifycmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

func TestMissingInputsAreUnknown(t *testing.T) {
	for _, endpoint := range []string{"src/app.py:3", "requirements.txt", "package-lock.json", "package.json"} {
		t.Run(endpoint, func(t *testing.T) {
			category := "deps"
			if endpoint == "src/app.py:3" {
				category = "secrets"
			}
			finding := models.Finding{ID: "SEC-1", Source: models.SourceWhitebox, Category: category, Endpoint: endpoint, Title: "fixture"}
			baseline := writeBaseline(t, t.TempDir(), []models.Finding{finding})
			result, err := Run(context.Background(), finding.ID, Options{BaselinePath: baseline, CodePath: t.TempDir()})
			if err != nil || result.Status != StatusUnknown {
				t.Fatalf("missing input: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestUnscannableNPMLockfileIsUnknown(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "package.json", `{"dependencies":{"example":"1.0.0"}}`)
	finding := models.Finding{ID: "SEC-1", Source: models.SourceWhitebox, Category: "deps", Endpoint: "package.json", Title: "fixture"}
	baseline := writeBaseline(t, t.TempDir(), []models.Finding{finding})
	result, err := Run(context.Background(), finding.ID, Options{BaselinePath: baseline, CodePath: root})
	if err != nil || result.Status != StatusUnknown {
		t.Fatalf("missing lockfile: result=%+v err=%v", result, err)
	}
}

func TestVerificationRejectsNonFileAndEscapingPaths(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	writeFile(t, outside, "secret.py", "fixture")
	if err := os.Mkdir(filepath.Join(root, "directory.py"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.py"), filepath.Join(root, "link.py")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(root, "directory.py"), filepath.Join(root, "link.py"), filepath.Join(outside, "secret.py")} {
		if err := inspectVerificationFile(root, path); err == nil {
			t.Fatalf("accepted unsafe input %s", path)
		}
	}
}

func TestVerificationUnreadableSourceIsInsufficient(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "source.py", "fixture")
	path := filepath.Join(root, "source.py")
	if err := inspectVerificationFile(root, path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0600) })
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file read permissions")
	}
	if err := inspectVerificationFile(root, path); err == nil {
		t.Fatal("unreadable source accepted")
	}
}

func TestHeaderVerificationRejectsErrorPagesWithSecureHeaders(t *testing.T) {
	for _, status := range []int{401, 403, 404, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Content-Type-Options", "nosniff")
				w.WriteHeader(status)
			}))
			defer server.Close()
			finding := models.Finding{ID: "SEC-1", Source: models.SourceBlackbox, Category: "headers", Endpoint: "GET /", Title: "Missing or incorrect X-Content-Type-Options header"}
			baseline := writeBaseline(t, t.TempDir(), []models.Finding{finding})
			result, err := Run(context.Background(), finding.ID, Options{BaselinePath: baseline, URL: server.URL})
			if err != nil || result.Status != StatusUnknown {
				t.Fatalf("error page: result=%+v err=%v", result, err)
			}
		})
	}
}
