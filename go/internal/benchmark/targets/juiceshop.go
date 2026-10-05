package targets

import (
	"context"
	"fmt"
	"time"

	"github.com/Fendix-app/Fendix/go/internal/benchmark"
)

const (
	// juiceShopImage is pinned to match `fendix demo` (democmd) so the
	// benchmark and the demo exercise the identical target build.
	juiceShopImage         = "bkimminich/juice-shop:v17.1.1"
	juiceShopHostPort      = 3000
	juiceShopContainerPort = 3000
	// juiceShopPortEnv moves the host port when 3000 is taken — which on a
	// developer machine it very often is (it is the default for every Node
	// dev server, including Juice Shop's own).
	juiceShopPortEnv = "FENDIX_BENCH_JUICESHOP_PORT"
)

// JuiceShop is the OWASP Juice Shop DAST benchmark target (Node app —
// black-box HTTP scanning, language-agnostic).
type JuiceShop struct {
	knownPath string
	hostPort  int
}

// NewJuiceShop returns a Juice Shop target reading ground truth from
// benchmarks/targets/juiceshop-known.json.
func NewJuiceShop() *JuiceShop {
	return &JuiceShop{knownPath: knownFilePath("juiceshop-known.json"), hostPort: portFromEnv(juiceShopPortEnv, juiceShopHostPort)}
}

// Name implements benchmark.BenchmarkTarget.
func (j *JuiceShop) Name() string { return "juiceshop" }

// Scan spins up Juice Shop in Docker, waits for it to come up, runs a
// stock black-box scan, and tears the container down.
func (j *JuiceShop) Scan(ctx context.Context, fendixBin string) (*benchmark.ScanResult, error) {
	c := container{
		name:          "fendix-bench-juiceshop",
		image:         juiceShopImage,
		hostPort:      j.hostPort,
		containerPort: juiceShopContainerPort,
		portEnv:       juiceShopPortEnv,
	}
	if err := c.start(ctx); err != nil {
		return nil, fmt.Errorf("juiceshop: %w", err)
	}
	defer c.stop()

	url := fmt.Sprintf("http://localhost:%d", j.hostPort)
	if err := waitForHTTP(ctx, url, 3*time.Minute, 3*time.Second); err != nil {
		return nil, fmt.Errorf("juiceshop: %w", err)
	}
	findings, dur, err := runFendixScan(ctx, fendixBin, []string{"--url", url})
	if err != nil {
		return nil, fmt.Errorf("juiceshop: %w", err)
	}
	return &benchmark.ScanResult{Findings: findings, ScanDuration: dur}, nil
}

// Run scores result against the Juice Shop ground truth.
func (j *JuiceShop) Run(ctx context.Context, result *benchmark.ScanResult) (*benchmark.BenchmarkResult, error) {
	ks, err := loadKnownSet(j.knownPath)
	if err != nil {
		return nil, fmt.Errorf("juiceshop: %w", err)
	}
	return score(j.Name(), ks, result.Findings, result.ScanDuration, time.Now()), nil
}
