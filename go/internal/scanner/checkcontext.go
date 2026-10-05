package scanner

import (
	"net/http"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// CheckContext is the per-scan execution context handed to every Check.Run.
//
// Client and NoFollow share ONE guarded transport (budget over netguard SSRF
// policy), so the SSRF egress guard + budget counting are identical on both.
// Client follows redirects and re-validates the resolved IP on every hop;
// NoFollow returns the raw 3xx (a redirect IS the signal for auth/idor/
// open-redirect/host-header). Checks MUST use one of these — never build their
// own transport. This is how the historical raw-budget.Transport() SSRF bypass
// is closed structurally.
//
// Audit is the scan-wide probe log; it aliases the package-global
// currentAuditLog() so GlobalAuditRecords()/--debug-bundle keep working.
type CheckContext struct {
	Cfg      *models.ScanConfig
	Client   *http.Client
	NoFollow *http.Client
	Audit    *ProbeAuditLog
}

// NewCheckContext builds the shared context once per scan. The shared clients
// set Timeout:0 — per-(endpoint,check) deadlines come from a context.WithTimeout
// inside the worker pool's runCheck, so one global Timeout cannot cap the whole
// scan under connection reuse.
func NewCheckContext(cfg *models.ScanConfig) *CheckContext {
	follow := guardedClient(cfg)
	follow.Timeout = 0
	return &CheckContext{
		Cfg:      cfg,
		Client:   follow,
		NoFollow: guardedClientNoFollow(cfg),
		Audit:    currentAuditLog(),
	}
}
