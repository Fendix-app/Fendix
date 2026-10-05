package targets

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/benchmark"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

func TestRealWorldLoudSkipWhenLocalPathAbsent(t *testing.T) {
	dir := t.TempDir()
	// A committed manifest that is local-only, with no local.yaml → SKIP.
	entry := filepath.Join(dir, "benchmarks", "realworld", "seed")
	os.MkdirAll(entry, 0o755)
	os.WriteFile(filepath.Join(entry, "manifest.yaml"),
		[]byte("name: seed\nlocal: true\n"), 0o644)
	os.WriteFile(filepath.Join(entry, "labels.yaml"), []byte("[]\n"), 0o644)

	rw := &RealWorld{root: dir, entryName: "seed"}
	_, err := rw.Scan(context.Background(), "fendix")
	if !errors.Is(err, ErrTargetSkipped) {
		t.Fatalf("Scan() should loud-SKIP when local path absent, got %v", err)
	}
}

func TestRealWorldRunScoresAndCountsLOC(t *testing.T) {
	dir := t.TempDir()
	entry := filepath.Join(dir, "benchmarks", "realworld", "mini")
	os.MkdirAll(entry, 0o755)
	os.WriteFile(filepath.Join(entry, "manifest.yaml"), []byte("name: mini\nlocal: true\n"), 0o644)
	os.WriteFile(filepath.Join(entry, "labels.yaml"),
		[]byte("- rule: PY_SSRF\n  file: app.py\n  line: 5\n  verdict: tp\n"), 0o644)
	// A source tree so LOC>0.
	src := filepath.Join(dir, "src")
	os.MkdirAll(src, 0o755)
	os.WriteFile(filepath.Join(src, "app.py"), []byte("import requests\nx=1\ny=2\nz=3\nrequests.get(u)\n"), 0o644)

	rw := &RealWorld{root: dir, entryName: "mini"}
	sr := &benchmark.ScanResult{Findings: []models.Finding{
		{ID: "SEC-PY_SSRF", Endpoint: "app.py:5"},
	}}
	rw.src = src // scored LOC comes from the resolved src
	res, err := rw.Run(context.Background(), sr)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.TruePos != 1 || res.FalsePos != 0 {
		t.Errorf("BenchmarkResult tp/fp = %d/%d, want 1/0", res.TruePos, res.FalsePos)
	}
	if rw.Result == nil || rw.Result.LOC == 0 {
		t.Fatalf("RealWorldResult not attached or LOC=0: %+v", rw.Result)
	}
}

func TestRealWorldPublicResolveUsesCache(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache", "app@abc123")
	os.MkdirAll(cache, 0o755)
	os.WriteFile(filepath.Join(cache, "x.py"), []byte("x=1\n"), 0o644)

	rw := &RealWorld{root: dir, entryName: "app", cacheRoot: filepath.Join(dir, "cache")}
	m := &realWorldManifest{Name: "app", Repo: "https://example.invalid/app.git", SHA: "abc123"}
	got, err := rw.resolveSourcePath(context.Background(), m)
	if err != nil {
		t.Fatalf("resolveSourcePath (cache hit): %v", err)
	}
	if got != cache {
		t.Errorf("resolveSourcePath = %q, want cached %q", got, cache)
	}
}

func TestRealWorldScoresTestdataMini(t *testing.T) {
	ls, err := benchmark.LoadLabelSet(filepath.Join("testdata", "realworld", "mini", "labels.yaml"))
	if err != nil {
		t.Fatalf("load testdata labels: %v", err)
	}
	// Synthetic scan result matching the committed fixture's real vuln.
	findings := []models.Finding{{ID: "SEC-PY_SSRF", Endpoint: "app.py:7"}}
	r := benchmark.ScoreRealWorld("mini", ls, findings, 12)
	if r.TruePos != 1 || r.FalsePos != 0 || r.Unknown != 0 || r.FalseNeg != 0 {
		t.Fatalf("mini score: tp=%d fp=%d unknown=%d fn=%d", r.TruePos, r.FalsePos, r.Unknown, r.FalseNeg)
	}
}

func TestRealWorldTriageReportGolden(t *testing.T) {
	ls := &benchmark.LabelSet{Labels: []benchmark.Label{
		{Rule: "PY_SSRF", File: "app.py", Line: 7, Verdict: benchmark.VerdictTP},
	}}
	findings := []models.Finding{
		{ID: "SEC-PY_SSRF", Endpoint: "app.py:7"},
		// Real production findings carry positional IDs; the UNKNOWN triage
		// line must be self-describing (CWE refs + title) so unknowns are
		// classifiable without re-running the scan.
		{ID: "SEC-PY_PATH_TRAVERSAL", Endpoint: "other.py:3",
			References: []string{"CWE-22"}, Title: "Potential path traversal"},
	}
	rw := &RealWorld{entryName: "mini"}
	rw.Result = benchmark.ScoreRealWorld("mini", ls, findings, 1000)
	got := rw.TriageReport()
	want, err := os.ReadFile(filepath.Join("testdata", "realworld", "mini", "triage.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("triage report mismatch:\n got: %q\nwant: %q", got, string(want))
	}
}

func TestDiscoverRealWorldEntries(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"twiscope", "sanad"} {
		e := filepath.Join(dir, "benchmarks", "realworld", name)
		os.MkdirAll(e, 0o755)
		os.WriteFile(filepath.Join(e, "manifest.yaml"), []byte("name: "+name+"\nlocal: true\n"), 0o644)
	}
	got := DiscoverRealWorld(dir)
	if len(got) != 2 {
		t.Fatalf("DiscoverRealWorld found %d, want 2", len(got))
	}
}

func TestCountLOCSkipsNonScannedDirs(t *testing.T) {
	// countLOC is the findings/KLOC denominator; it must count the same
	// tree the scanner walks. The analyzers skip vendored/venv dirs
	// (python/analyzers/ast_analyzer.py _SKIP_DIRS), so counting them here
	// would deflate density ~8x on a real repo with a checked-in .venv.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.py"), []byte("a=1\nb=2\n"), 0o644)
	for _, skip := range []string{".venv", "node_modules", ".git", "__pycache__"} {
		sub := filepath.Join(dir, skip)
		os.MkdirAll(sub, 0o755)
		os.WriteFile(filepath.Join(sub, "big.py"), []byte("x=1\nx=2\nx=3\nx=4\n"), 0o644)
	}
	if got := countLOC(dir); got != 2 {
		t.Errorf("countLOC = %d, want 2 (skip-dirs must be excluded)", got)
	}
}
