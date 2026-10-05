package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/embedded"
)

func TestEnsureEngine_ExplicitDir(t *testing.T) {
	// Create a temp dir with engine.py
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "engine.py"), []byte("# engine"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := EnsureEngine(dir, "dev")
	if err != nil {
		t.Fatalf("EnsureEngine failed: %v", err)
	}
	if result != dir {
		t.Errorf("expected %s, got %s", dir, result)
	}
}

func TestEnsureEngine_ExplicitDir_Missing(t *testing.T) {
	dir := t.TempDir() // No engine.py here
	_, err := EnsureEngine(dir, "dev")
	if err == nil {
		t.Fatal("expected error for missing engine.py")
	}
}

func TestEnsureEngine_FallbackToLocal(t *testing.T) {
	if embedded.HasEngine() {
		t.Skip("engine is embedded — cannot test local fallback")
	}

	// Isolate HOME so a real ~/.fendix/config pin on the dev machine (written
	// by a prior `fendix engine sync`) can't shadow the CWD "python" fallback
	// we're exercising here — step 2b would otherwise return the pinned
	// absolute path before step 4 runs. Also clear FENDIX_ENGINE for the same
	// reason. t.Setenv restores both on cleanup.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("FENDIX_ENGINE", "")

	// Test that when no embedded engine and no explicit dir, it tries local "python"
	// This test's behavior depends on CWD
	result, err := EnsureEngine("", "dev")

	// If we're running from the project root, python/engine.py exists
	if err == nil {
		if result != "python" {
			t.Errorf("expected 'python', got %s", result)
		}
	}
	// If not at project root, error is expected — that's fine
}

func TestEnsureEngine_EmbeddedExtraction(t *testing.T) {
	if !embedded.HasEngine() {
		t.Skip("no engine embedded — run with embed-engine to test")
	}

	// Override home dir for extraction
	origHome := os.Getenv("HOME")
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	defer os.Setenv("HOME", origHome)

	result, err := EnsureEngine("", "1.0.0")
	if err != nil {
		t.Fatalf("EnsureEngine failed: %v", err)
	}

	// Should have extracted to tmpHome/.fendix/engine/
	expectedDir := filepath.Join(tmpHome, ".fendix", "engine")
	if result != expectedDir {
		t.Errorf("expected %s, got %s", expectedDir, result)
	}

	// engine.py should exist
	if _, err := os.Stat(filepath.Join(result, "engine.py")); err != nil {
		t.Errorf("engine.py not found: %v", err)
	}

	// Version stamp should exist
	stamp, err := os.ReadFile(filepath.Join(result, VersionFile))
	if err != nil {
		t.Errorf("version stamp not found: %v", err)
	}
	if string(stamp) != "1.0.0" {
		t.Errorf("expected version stamp '1.0.0', got '%s'", stamp)
	}
}

func TestEnsureEngine_SkipsReExtraction(t *testing.T) {
	if !embedded.HasEngine() {
		t.Skip("no engine embedded — run with embed-engine to test")
	}

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// First extraction
	_, err := EnsureEngine("", "1.0.0")
	if err != nil {
		t.Fatalf("first extraction failed: %v", err)
	}

	// Second call should not re-extract (same version)
	result, err := EnsureEngine("", "1.0.0")
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if result == "" {
		t.Fatal("expected non-empty result")
	}
}

func TestEnsureEngine_ReExtractsOnVersionChange(t *testing.T) {
	if !embedded.HasEngine() {
		t.Skip("no engine embedded — run with embed-engine to test")
	}

	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// First extraction with v1
	_, err := EnsureEngine("", "1.0.0")
	if err != nil {
		t.Fatalf("v1 extraction failed: %v", err)
	}

	engineDir := filepath.Join(tmpHome, ".fendix", "engine")

	// Check version is 1.0.0
	stamp, _ := os.ReadFile(filepath.Join(engineDir, VersionFile))
	if string(stamp) != "1.0.0" {
		t.Fatalf("expected 1.0.0, got %s", stamp)
	}

	// Second extraction with v2 should re-extract
	_, err = EnsureEngine("", "2.0.0")
	if err != nil {
		t.Fatalf("v2 extraction failed: %v", err)
	}

	stamp, _ = os.ReadFile(filepath.Join(engineDir, VersionFile))
	if string(stamp) != "2.0.0" {
		t.Errorf("expected version stamp '2.0.0', got '%s'", stamp)
	}
}

func TestNeedsExtraction_MissingEngineFile(t *testing.T) {
	dir := t.TempDir()
	if !needsExtraction(dir, "1.0.0") {
		t.Error("expected needsExtraction=true when engine.py missing")
	}
}

func TestNeedsExtraction_MissingVersionStamp(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "engine.py"), []byte("# engine"), 0o644)
	if !needsExtraction(dir, "1.0.0") {
		t.Error("expected needsExtraction=true when version stamp missing")
	}
}

func TestNeedsExtraction_SameVersion(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "engine.py"), []byte("# engine"), 0o644)
	os.WriteFile(filepath.Join(dir, VersionFile), []byte("1.0.0"), 0o644)
	if needsExtraction(dir, "1.0.0") {
		t.Error("expected needsExtraction=false when version matches")
	}
}

func TestNeedsExtraction_DifferentVersion(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "engine.py"), []byte("# engine"), 0o644)
	os.WriteFile(filepath.Join(dir, VersionFile), []byte("1.0.0"), 0o644)
	if !needsExtraction(dir, "2.0.0") {
		t.Error("expected needsExtraction=true when version differs")
	}
}

func TestNeedsExtraction_DevVersion(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "engine.py"), []byte("# engine"), 0o644)
	// No version stamp, but dev version — should not re-extract
	os.WriteFile(filepath.Join(dir, VersionFile), []byte("old"), 0o644)
	if needsExtraction(dir, "dev") {
		t.Error("expected needsExtraction=false for dev version with existing engine")
	}
}
