package semgrep

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestFastAPIAuthRule_FrameworkScoping pins the contract that the
// `fastapi-route-missing-auth-dependency` rule fires ONLY on real,
// unauthenticated FastAPI routes — not on Django/DRF/Celery decorators that
// merely share the `@x.y(...)` shape. This is the regression guard for the
// TwiScope false-positive class (v0.18.x), where the old, ungated rule
// flagged @shared_task / @action / @extend_schema_field / @field_validator
// as "FastAPI routes missing auth" on Django and Pydantic code.
//
// It also pins that the FastAPI auth idioms — Depends(), Security(), and
// PEP-593 Annotated[...] — are recognised and not falsely flagged.
//
// Skipped when semgrep is not on PATH, and failed instead when
// FENDIX_REQUIRE_SEMGREP is set (requireSemgrep, as in CI): the YAML-only
// catalog tests can't see matching behaviour, so this runs where semgrep is
// installed (local dev + semgrep-enabled CI).
func TestFastAPIAuthRule_FrameworkScoping(t *testing.T) {
	bin := requireSemgrep(t)
	resetRulesCacheForTesting()
	dir, err := ensureRules()
	if err != nil {
		t.Fatalf("ensureRules: %v", err)
	}
	cfg := filepath.Join(dir, "auth.yaml")

	fixtures := map[string]string{
		// --- Non-FastAPI: must NEVER be flagged (no fastapi import) ---
		"django_proj/views.py": `from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet
class V(ViewSet):
    @action(detail=False, methods=["get"])
    def stats(self, request):
        return request
`,
		"django_proj/tasks.py": `from celery import shared_task
@shared_task(bind=True, name="x")
def evaluate(self, n):
    return n
`,
		"django_proj/serializers.py": `from drf_spectacular.utils import extend_schema_field
from drf_spectacular.types import OpenApiTypes
class S:
    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_item(self, obj):
        return obj
`,
		// Pydantic validators in a FastAPI file — @field_validator is not a
		// route and must not be flagged even though fastapi is imported.
		"api/schemas.py": `from fastapi import APIRouter
from pydantic import BaseModel, field_validator
class M(BaseModel):
    name: str
    @field_validator("name")
    @classmethod
    def not_empty(cls, v):
        return v
`,
		// --- Real FastAPI routes ---
		"api/routes.py": `from fastapi import APIRouter, Depends, Security
from typing import Annotated
router = APIRouter()

@router.get("/open")
async def open_ep():            # UNAUTHED -> the only finding expected
    return {}

@router.get("/authed")
def authed(user = Depends(get_current_user)):   # Depends -> not flagged
    return user

@router.get("/annotated")
async def annotated(user: Annotated[dict, Depends(get_current_user)]):  # Annotated -> not flagged
    return user

@router.get("/secured")
def secured(user = Security(scheme)):           # Security -> not flagged
    return user
`,
	}

	root := t.TempDir()
	for rel, body := range fixtures {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command(bin, "scan", "--config", cfg, "--json", "--no-git-ignore", "--quiet", root)
	// semgrep exits 1 when it finds matches; the JSON envelope is still valid,
	// so we ignore the exit code and parse stdout (same posture as Scan()).
	out, _ := cmd.Output()

	var res struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int `json:"line"`
			} `json:"start"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("parse semgrep json: %v\noutput:\n%s", err, string(out))
	}

	var faFiles []string
	for _, r := range res.Results {
		if !strings.Contains(r.CheckID, "fastapi-route-missing-auth") {
			continue
		}
		rel, _ := filepath.Rel(root, r.Path)
		faFiles = append(faFiles, filepath.ToSlash(rel))
	}

	// No non-FastAPI / non-route file may be flagged.
	for _, f := range faFiles {
		if strings.HasPrefix(f, "django_proj/") || f == "api/schemas.py" {
			t.Errorf("FALSE POSITIVE: flagged non-route file %s", f)
		}
	}

	// Exactly one finding total: the single unauthed route in routes.py. A
	// count != 1 means either the unauthed route was missed (FN) or an authed
	// route / non-route was flagged (FP).
	if len(faFiles) != 1 || faFiles[0] != "api/routes.py" {
		t.Errorf("expected exactly 1 fastapi-auth finding in api/routes.py (the unauthed route), got %v", faFiles)
	}
}
