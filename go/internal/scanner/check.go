package scanner

import (
	"context"

	ev "github.com/Fendix-app/Fendix/go/internal/evidence"
	"github.com/Fendix-app/Fendix/go/internal/models"
)

// Tier classifies a check by intrusiveness and required scan inputs. The
// orchestrator filters DefaultChecks() by Enabled(cfg) and prints the
// active-scanning disclaimer iff any enabled check is TierActive.
//
// Tier values are append-only: the iota int is never persisted, but
// renumbering existing values is a needless footgun. Add new tiers at the end.
type Tier int

const (
	TierPassive   Tier = iota // safe GET/OPTIONS observation; always on
	TierActive                // sends attack payloads; gated by cfg.EnableActive
	TierAuth                  // needs cfg.Auth (single credential)
	TierMultiuser             // needs cfg.Auth AND cfg.AuthUser2 (cross-user)
)

func (t Tier) String() string {
	switch t {
	case TierPassive:
		return "passive"
	case TierActive:
		return "active"
	case TierAuth:
		return "auth"
	case TierMultiuser:
		return "multiuser"
	default:
		return "unknown"
	}
}

// Check is the unit of black-box detection. Implementations are stateless
// adapter structs registered in DefaultChecks().
type Check interface {
	Name() string                        // stable id, e.g. "configleak"
	Category() string                    // ev.Evidence.Category bucket
	Tier() Tier                          // intrusiveness / input class
	Enabled(cfg *models.ScanConfig) bool // tier-implied gate
	Run(ctx context.Context, cc *CheckContext, ep Endpoint) []ev.Evidence
}

// AsCheck adapts an existing free CheckFn into the Check interface so the
// engine worker-pool tests (which pass []scanner.CheckFn) keep compiling. The
// adapter reads cfg/audit from the CheckContext.
func AsCheck(name, category string, tier Tier, enabled func(*models.ScanConfig) bool, fn CheckFn) Check {
	return fnCheck{name: name, category: category, tier: tier, enabled: enabled, fn: fn}
}

type fnCheck struct {
	name     string
	category string
	tier     Tier
	enabled  func(*models.ScanConfig) bool
	fn       CheckFn
}

func (c fnCheck) Name() string                        { return c.name }
func (c fnCheck) Category() string                    { return c.category }
func (c fnCheck) Tier() Tier                          { return c.tier }
func (c fnCheck) Enabled(cfg *models.ScanConfig) bool { return c.enabled == nil || c.enabled(cfg) }
func (c fnCheck) Run(ctx context.Context, cc *CheckContext, ep Endpoint) []ev.Evidence {
	return c.fn(ctx, cc.Cfg, ep)
}

// DefaultChecks returns the full ordered check registry. configleak is first
// so its CRITICAL "exposed config file" finding lands before noisier
// per-endpoint checks on the same path (dedup ordering). The orchestrator
// filters this slice by Enabled(cfg) at scan time.
func DefaultChecks() []Check {
	return []Check{
		configLeakCheck{},
		headersCheck{},
		corsCheck{},
		exposureCheck{},
		rateLimitCheck{},
		cookieFlagsCheck{},
		authCheck{},
		idorCheck{},
		injectionCheck{},
		openRedirectCheck{},
		reflectedXSSCheck{},
		SSRFCheck{},
		hostHeaderCheck{},
		graphQLCheck{},
		methodTamperCheck{},
		// proof checks (Phase 1) and new types (Phases 6-9) appended here.
	}
}
