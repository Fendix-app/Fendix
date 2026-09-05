package neterr

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want Kind
	}{
		{"nil", nil, KindOther},
		{"plain", errors.New("boom"), KindOther},
		{"deadline", context.DeadlineExceeded, KindTimeout},
		{"net timeout", timeoutErr{}, KindTimeout},
		{"url error wrapping refused", &url.Error{Op: "Post", URL: "https://api.osv.dev", Err: syscall.ECONNREFUSED}, KindNetwork},
		{"dns", &net.DNSError{Err: "no such host", Name: "api.osv.dev"}, KindNetwork},
		{"reset wrapped", fmt.Errorf("post batch: %w", syscall.ECONNRESET), KindNetwork},
		{"503", fmt.Errorf("osv batch: %w", &StatusError{Host: "https://api.osv.dev", Code: 503}), KindNetwork},
		{"429", &StatusError{Host: "h", Code: 429}, KindNetwork},
		{"404 is not transient", &StatusError{Host: "h", Code: 404}, KindOther},
		{"lookup error unwraps", &LookupError{Scanner: "pip", Failed: 3, Total: 3, Cause: &StatusError{Host: "h", Code: 502}}, KindNetwork},
		{"subprocess network sentinel", fmt.Errorf("govulncheck: %w", ErrSubprocessNetwork), KindNetwork},
		{"subprocess timeout sentinel", fmt.Errorf("govulncheck: %w", ErrSubprocessTimeout), KindTimeout},
	} {
		if got := Classify(tc.err); got != tc.want {
			t.Errorf("%s: Classify = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestClassifyText(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Kind
	}{
		{"Get \"https://vuln.go.dev/index/db.json\": dial tcp: lookup vuln.go.dev: no such host", KindNetwork},
		{"dial tcp 1.2.3.4:443: connect: connection refused", KindNetwork},
		{"read tcp: connection reset by peer", KindNetwork},
		{"tls: handshake failure", KindNetwork},
		{"context deadline exceeded (Client.Timeout exceeded while awaiting headers)", KindTimeout},
		{"i/o timeout", KindTimeout},
		{"govulncheck: package x: no Go files", KindOther},
		{"", KindOther},
	} {
		if got := ClassifyText(tc.in); got != tc.want {
			t.Errorf("%q: ClassifyText = %v, want %v", tc.in, got, tc.want)
		}
	}
}
