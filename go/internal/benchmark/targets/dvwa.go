package targets

import (
	"context"
	"fmt"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/benchmark"
)

const (
	// dvwaImage is the classic Damn Vulnerable Web App container (PHP).
	// DAST is language-agnostic, so PHP is irrelevant to the HTTP probe.
	// Digest-pinned for a reproducible baseline (DVWA only publishes :latest;
	// dvwa-known.json is triaged against this exact image) — same discipline as
	// Juice Shop's v17.1.1 tag pin (v0.28 deferred item, closed).
	dvwaImage         = "vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7"
	dvwaHostPort      = 8080
	dvwaPortEnv       = "FENDIX_BENCH_DVWA_PORT"
	dvwaContainerPort = 80
)

// DVWA is the Damn Vulnerable Web App DAST benchmark target.
//
// LIMITATION (documented for honesty, roadmap Rule 5): most DVWA
// vulnerabilities live behind a login + a one-time DB setup at
// /setup.php, and behind a security-level cookie. An unauthenticated
// black-box scan reaches only the surface (headers, exposed setup, cookie
// flags). Authenticated DVWA scanning is a v0.21+ enhancement; until then
// the ground-truth list is deliberately scoped to what an unauthenticated
// scan can actually reach, so recall numbers stay honest.
type DVWA struct {
	knownPath string
	hostPort  int
}

// NewDVWA returns a DVWA target reading ground truth from
// benchmarks/targets/dvwa-known.json.
func NewDVWA() *DVWA {
	return &DVWA{knownPath: knownFilePath("dvwa-known.json"), hostPort: portFromEnv(dvwaPortEnv, dvwaHostPort)}
}

// Name implements benchmark.BenchmarkTarget.
func (d *DVWA) Name() string { return "dvwa" }

// Scan spins up DVWA in Docker, waits for it, runs a black-box scan, and
// tears the container down.
func (d *DVWA) Scan(ctx context.Context, fendixBin string) (*benchmark.ScanResult, error) {
	c := container{
		name:          "fendix-bench-dvwa",
		image:         dvwaImage,
		hostPort:      d.hostPort,
		containerPort: dvwaContainerPort,
		portEnv:       dvwaPortEnv,
	}
	if err := c.start(ctx); err != nil {
		return nil, fmt.Errorf("dvwa: %w", err)
	}
	defer c.stop()

	url := fmt.Sprintf("http://localhost:%d", d.hostPort)
	if err := waitForHTTP(ctx, url, 2*time.Minute, 3*time.Second); err != nil {
		return nil, fmt.Errorf("dvwa: %w", err)
	}
	findings, dur, err := runFendixScan(ctx, fendixBin, []string{"--url", url})
	if err != nil {
		return nil, fmt.Errorf("dvwa: %w", err)
	}
	return &benchmark.ScanResult{Findings: findings, ScanDuration: dur}, nil
}

// Run scores result against the DVWA ground truth.
func (d *DVWA) Run(ctx context.Context, result *benchmark.ScanResult) (*benchmark.BenchmarkResult, error) {
	ks, err := loadKnownSet(d.knownPath)
	if err != nil {
		return nil, fmt.Errorf("dvwa: %w", err)
	}
	return score(d.Name(), ks, result.Findings, result.ScanDuration, time.Now()), nil
}
