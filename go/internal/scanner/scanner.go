// Package scanner implements HTTP-based black-box security checks.
// Each check is a function that takes a scan config and endpoint,
// sends HTTP requests, and returns findings based on the responses.
package scanner

import (
	"context"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Endpoint represents a discovered API endpoint to scan.
//
// Params holds query and path parameter names (covered by TASK-081).
// Headers holds OpenAPI `in: header` parameter names with standard auth
// headers (Authorization, Cookie, X-Api-Key, ...) filtered out — those are
// the auth scanner's job, and probing them with malicious payloads risks
// breaking the test session for downstream endpoints.
// BodyParams holds JSON body field names extracted from `requestBody`
// (OpenAPI 3) or `in: body` schema (Swagger 2). Probing them requires
// emitting a JSON body on POST/PUT/PATCH; see CheckInjectionWithAudit.
type Endpoint struct {
	Method     string
	Path       string
	FullURL    string
	Params     []string
	Headers    []string
	BodyParams []string
	// AuthExpectation is what a source of truth (today: the OpenAPI spec)
	// declares about authentication for this operation. Zero value = unknown,
	// which is what every non-spec discovery source (crawl, brute-force,
	// robots.txt, JS extraction) leaves it as — correctly, since those observe
	// that a path EXISTS and nothing about whether it should be gated.
	//
	// The auth check reads it to distinguish "this endpoint is public" from
	// "this endpoint's authentication requirement was bypassed"; without it,
	// checkUnauthenticated could only see a status code and called every 2xx
	// CRITICAL (RC-2).
	AuthExpectation models.AuthExpectation
}

// CheckFn is the signature for all scanner check functions.
// Each check receives a context, config, and endpoint, and returns findings.
type CheckFn func(ctx context.Context, cfg *models.ScanConfig, endpoint Endpoint) []ev.Evidence
