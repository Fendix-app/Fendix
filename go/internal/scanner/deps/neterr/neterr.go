// Package neterr types the transport failures the dependency scanners see
// so the orchestrator can classify them as network_error or timeout
// without reading error prose. Only the govulncheck subprocess, whose
// library returns untyped errors, falls back to a fixed list of Go's own
// net error wordings (ClassifyText) — an engine-internal transport hint,
// never a contract value.
package neterr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
)

// Kind is the transport classification of an error.
type Kind int

const (
	KindOther Kind = iota
	KindNetwork
	KindTimeout
)

func (k Kind) String() string {
	switch k {
	case KindNetwork:
		return "network"
	case KindTimeout:
		return "timeout"
	}
	return "other"
}

// StatusError is a non-2xx answer from a vulnerability database. 5xx and
// 429 are transient (the service, not the request, is the problem); every
// other status is a request-side fact and is never retried.
type StatusError struct {
	Host string
	Code int
}

func (e *StatusError) Error() string { return fmt.Sprintf("%s returned HTTP %d", e.Host, e.Code) }

// Transient reports whether the status is worth one retry.
func (e *StatusError) Transient() bool { return e.Code == 429 || e.Code >= 500 }

// LookupError reports that some package lookups failed after every
// fallback. Findings for the packages that did resolve are still returned
// by the scanner alongside this error (Rule 3); the coverage entry says
// the pass did not deliver.
type LookupError struct {
	Scanner string
	Failed  int
	Total   int
	Cause   error
}

func (e *LookupError) Error() string {
	return fmt.Sprintf("%s: %d of %d package lookups failed: %v", e.Scanner, e.Failed, e.Total, e.Cause)
}

func (e *LookupError) Unwrap() error { return e.Cause }

// Failures accumulates package-lookup failures across a scan so the
// scanner can keep the findings that DID resolve while still reporting a
// typed error for the ones that didn't. Shared by pip and npm rather than
// duplicated per package, since both walk the same
// batch-then-serial-fallback shape.
//
// A batch failure that falls back to serial does not count on its own —
// only Note the failure once every fallback for that package is
// exhausted. Safe for concurrent use: the batch path notes failures from
// multiple chunk goroutines.
type Failures struct {
	mu     sync.Mutex
	failed int
	last   error
}

// Note records one package's lookup as failed, keeping the most recent
// cause for classification.
func (f *Failures) Note(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failed++
	f.last = err
}

// Err returns nil when nothing failed, else a *LookupError naming how
// many of total lookups failed and wrapping the last-seen cause.
func (f *Failures) Err(scanner string, total int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failed == 0 {
		return nil
	}
	return &LookupError{Scanner: scanner, Failed: f.failed, Total: total, Cause: f.last}
}

// Sentinels a subprocess-based scanner wraps after typing its stderr.
var (
	ErrSubprocessNetwork = errors.New("network failure reported by subprocess")
	ErrSubprocessTimeout = errors.New("timeout reported by subprocess")
)

// Classify types err by unwrapping to a known transport error.
func Classify(err error) Kind {
	if err == nil {
		return KindOther
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrSubprocessTimeout) {
		return KindTimeout
	}
	if errors.Is(err, ErrSubprocessNetwork) {
		return KindNetwork
	}
	var se *StatusError
	if errors.As(err, &se) {
		if se.Transient() {
			return KindNetwork
		}
		return KindOther
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return KindTimeout
		}
		return KindNetwork
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return KindNetwork
	}
	var rhe tls.RecordHeaderError
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(err, &rhe) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) {
		return KindNetwork
	}
	return KindOther
}

// textNetworkMarkers are Go's own net/http and net wordings for transport
// failures, used only to type a subprocess's stderr.
var textNetworkMarkers = []string{
	"dial tcp", "no such host", "connection refused", "connection reset",
	"network is unreachable", "no route to host", "tls: ", "tls handshake",
	"temporary failure in name resolution", "server misbehaving",
	" 502", " 503", " 504", " 429",
}

// ClassifyText types a subprocess's stderr.
func ClassifyText(stderr string) Kind {
	l := strings.ToLower(stderr)
	if l == "" {
		return KindOther
	}
	if strings.Contains(l, "i/o timeout") || strings.Contains(l, "deadline exceeded") || strings.Contains(l, "timeout exceeded") {
		return KindTimeout
	}
	for _, m := range textNetworkMarkers {
		if strings.Contains(l, m) {
			return KindNetwork
		}
	}
	return KindOther
}
