package reporters

import (
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
	"github.com/Abdel-RahmanSaied/Fendix/internal/reporters/i18n"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="{{.Lang}}"{{if .RTL}} dir="rtl"{{end}}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.I18n.ReportTitle}}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6;padding:2rem}
{{if .RTL}}/* Sprint 10 RTL branch */
body,table,.toolbar,.summary,.finding-header,.field{direction:rtl}
th,td,.field-label,.field-value,.subtitle,.meta{text-align:right}
.affected-list{padding-right:1.25rem;padding-left:0}
.finding-id{margin-right:0;margin-left:.5rem}
{{end}}
.container{max-width:1200px;margin:0 auto}
h1{font-size:1.75rem;margin-bottom:.5rem;color:#f8fafc}
.subtitle{color:#94a3b8;margin-bottom:2rem}
.summary{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}
.stat{padding:1rem 1.5rem;border-radius:.75rem;min-width:120px;text-align:center}
.stat .count{font-size:2rem;font-weight:700}
.stat .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;opacity:.8}
.stat.critical{background:#450a0a;border:1px solid #dc2626;color:#fca5a5}
.stat.high{background:#431407;border:1px solid #ea580c;color:#fdba74}
.stat.medium{background:#422006;border:1px solid #d97706;color:#fcd34d}
.stat.low{background:#1e3a5f;border:1px solid #3b82f6;color:#93c5fd}
.stat.info{background:#1e293b;border:1px solid #475569;color:#94a3b8}
.stat.block{background:#450a0a;border:1px solid #ef4444;color:#fecaca}
.stat.confirmed{background:#052e16;border:1px solid #22c55e;color:#86efac}
.toolbar{display:flex;gap:.75rem;margin-bottom:1rem;align-items:center;flex-wrap:wrap}
.toolbar button{background:#334155;color:#e2e8f0;border:1px solid #475569;border-radius:.5rem;padding:.4rem 1rem;font-size:.8rem;cursor:pointer;transition:background .15s}
.toolbar button:hover{background:#475569}
.toolbar button.active{background:#3b82f6;border-color:#3b82f6;color:#fff}
.toolbar .sort-label{color:#64748b;font-size:.8rem}
.findings{margin-top:1rem}
.finding{background:#1e293b;border:1px solid #334155;border-radius:.75rem;margin-bottom:.75rem;overflow:hidden}
.finding-header{display:flex;align-items:center;gap:.75rem;padding:1rem 1.25rem;cursor:pointer;user-select:none}
.finding-header:hover{background:#253349}
.badge{padding:.25rem .75rem;border-radius:9999px;font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.badge.CRITICAL{background:#dc2626;color:#fff}
.badge.HIGH{background:#ea580c;color:#fff}
.badge.MEDIUM{background:#d97706;color:#1c1917}
.badge.LOW{background:#3b82f6;color:#fff}
.badge.INFO{background:#475569;color:#e2e8f0}
.finding-id{color:#64748b;font-size:.75rem;font-family:monospace;min-width:4rem}
.finding-title{flex:1;font-weight:500}
.finding-endpoint{color:#94a3b8;font-size:.85rem;font-family:monospace}
.toggle{font-size:1.25rem;color:#64748b;transition:transform .2s}
.finding.open .toggle{transform:rotate(90deg)}
.finding-body{display:none;padding:1rem 1.25rem;border-top:1px solid #334155;font-size:.9rem}
.finding.open .finding-body{display:block}
.field{margin-bottom:.75rem}
.field-label{color:#64748b;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-bottom:.25rem}
.field-value{color:#cbd5e1}
.evidence{background:#0f172a;padding:.75rem;border-radius:.5rem;font-family:monospace;font-size:.8rem;word-break:break-all;color:#fbbf24}
.affected-list{margin:0;padding-left:1.25rem;font-family:monospace;font-size:.85rem;list-style:disc}
.affected-list li{margin:.1rem 0}
.finding-endpoint em{color:#fbbf24;font-style:normal;font-size:.75rem}
.meta{margin-top:2rem;padding-top:1.5rem;border-top:1px solid #334155;color:#64748b;font-size:.8rem;display:flex;gap:2rem;flex-wrap:wrap}
@media print{
body{background:#fff;color:#1e293b;padding:1rem}
.container{max-width:100%}
.finding{break-inside:avoid;border-color:#ccc}
.finding.open .finding-body{display:block}
.finding-body{display:block !important}
.stat{border-color:#ccc !important;background:#f8f9fa !important;color:#1e293b !important}
.stat.critical{border-color:#dc2626 !important}
.stat.high{border-color:#ea580c !important}
.stat.medium{border-color:#d97706 !important}
.stat.low{border-color:#3b82f6 !important}
.badge.CRITICAL{background:#dc2626}
.badge.HIGH{background:#ea580c}
.badge.MEDIUM{background:#d97706}
.badge.LOW{background:#3b82f6}
.badge.INFO{background:#94a3b8}
.finding-header{background:#f1f5f9}
.evidence{background:#f1f5f9;color:#92400e}
.toolbar{display:none}
.meta{border-color:#ccc;color:#64748b}
}
.verdict{padding:12px 16px;border-radius:8px;font-weight:600;margin:0 0 16px}
.verdict-block{background:#3b0d0d;color:#ffb4b4}.verdict-incomplete{background:#3a2e08;color:#ffd97a}
.verdict-warn{background:#3a2e08;color:#ffd97a}.verdict-pass{background:#0f2e1a;color:#9ae6b4}
.coverage-table{width:100%;border-collapse:collapse;font-size:13px}.coverage-table th,.coverage-table td{text-align:start;padding:4px 8px;border-bottom:1px solid #2a2a2a}
.coverage-verdict.gap{color:#ffd97a}.coverage-verdict.ok{color:#9ae6b4}
tr.cov-failed td,tr.cov-unavailable td,tr.cov-unknown td{color:#ffb4b4}tr.cov-unsupported td,tr.cov-disabled td{color:#bdbdbd}
</style>
</head>
<body>
<div class="container">
<h1>&#x1f6e1; {{.I18n.ReportTitle}}</h1>
<p class="subtitle">{{.Metadata.Target}} &mdash; {{.Metadata.Mode}} scan &mdash; {{.Metadata.Duration}}</p>
{{if .Metadata.ReleaseDecision}}<div class="verdict verdict-{{.Metadata.ReleaseDecision}}{{if eq .Metadata.CoverageState "incomplete"}} verdict-partial{{end}}">{{verdictLabel .Metadata.ReleaseDecision .Metadata.CoverageState}}</div>{{end}}
<div class="summary">
<div class="stat critical"><div class="count">{{.Summary.Critical}}</div><div class="label">{{.I18n.SeverityCritical}}</div></div>
<div class="stat high"><div class="count">{{.Summary.High}}</div><div class="label">{{.I18n.SeverityHigh}}</div></div>
<div class="stat medium"><div class="count">{{.Summary.Medium}}</div><div class="label">{{.I18n.SeverityMedium}}</div></div>
<div class="stat low"><div class="count">{{.Summary.Low}}</div><div class="label">{{.I18n.SeverityLow}}</div></div>
<div class="stat info"><div class="count">{{.Summary.Info}}</div><div class="label">{{.I18n.SeverityInfo}}</div></div>
<div class="stat block"><div class="count">{{.Decisions.Blocking}}</div><div class="label">{{.I18n.StatusBlocking}}</div></div>
<div class="stat confirmed"><div class="count">{{.Decisions.Confirmed}}</div><div class="label">{{.I18n.StatusConfirmed}}</div></div>
</div>
<div class="toolbar">
<span class="sort-label">{{.I18n.SortByLabel}}</span>
<button class="active" onclick="sortFindings('severity',this)">{{.I18n.SortBySeverity}}</button>
<button onclick="sortFindings('endpoint',this)">{{.I18n.SortByEndpoint}}</button>
<button onclick="sortFindings('source',this)">{{.I18n.SortBySource}}</button>
<span style="flex:1"></span>
<button onclick="toggleAll(true)">{{.I18n.ExpandAll}}</button>
<button onclick="toggleAll(false)">{{.I18n.CollapseAll}}</button>
</div>
<div class="findings" id="findings">
{{range .Findings}}<div class="finding" data-severity="{{severityRank .Severity}}" data-endpoint="{{.Endpoint}}" data-source="{{.Source}}" onclick="this.classList.toggle('open')">
<div class="finding-header">
<span class="badge {{.Severity}}">{{.Severity}}</span>
<span class="finding-id">{{.ID}}</span>
<span class="finding-title">{{.Title}}</span>
<span class="finding-endpoint">{{.Endpoint}}{{if gt (len .AffectedEndpoints) 1}} <em>(+{{sub (len .AffectedEndpoints) 1}} more)</em>{{end}}</span>
<span class="toggle">&#x25B6;</span>
</div>
<div class="finding-body">
<div class="field"><div class="field-label">{{$.I18n.FieldEvidence}}</div><div class="evidence">{{.Evidence}}</div></div>
<div class="field"><div class="field-label">{{$.I18n.FieldFix}}</div><div class="field-value">{{.Fix}}</div></div>
<div class="field"><div class="field-label">{{$.I18n.FieldSource}}</div><div class="field-value">{{.Source}} &middot; {{.Confidence}} {{$.I18n.ConfidenceLabel}}{{if .ConfidenceScore}} ({{.ConfidenceScore}}/100){{end}}{{if .Status}} &middot; {{.Status}}{{end}}</div></div>
<div class="field"><div class="field-label">{{$.I18n.FieldCategory}}</div><div class="field-value">{{.Category}}</div></div>
{{if gt (len .AffectedEndpoints) 1}}<div class="field"><div class="field-label">{{$.I18n.FieldAffected}} ({{len .AffectedEndpoints}})</div><div class="field-value"><ul class="affected-list">{{range .AffectedEndpoints}}<li>{{.}}</li>{{end}}</ul></div></div>{{end}}
{{if .Reachable}}<div class="field"><div class="field-label">{{$.I18n.FieldReachable}} ({{len .TaintChain}})</div><div class="field-value"><ol class="affected-list">{{range .TaintChain}}<li><code>{{.File}}:{{.Line}}</code> &mdash; <code>{{.Expr}}</code></li>{{end}}</ol></div></div>{{end}}
{{if .References}}<div class="field"><div class="field-label">{{$.I18n.FieldReferences}}</div><div class="field-value">{{joinRefs .References}}</div></div>{{end}}
{{if .Line}}<div class="field"><div class="field-label">{{$.I18n.FieldLocation}}</div><div class="field-value">{{derefLine .Line}}</div></div>{{end}}
</div>
</div>
{{end}}</div>
<div class="meta">
<span>{{.I18n.ScanStartedLabel}} {{formatTime .Metadata.StartedAt}}</span>
<span>{{.I18n.DurationLabel}} {{.Metadata.Duration}}</span>
<span>{{.I18n.ModeLabel}} {{.Metadata.Mode}}</span>
<span>{{.I18n.EndpointsLabel}} {{.Metadata.EndpointsCount}}</span>
<span>{{.I18n.TotalFindingsLabel}} {{.Total}}</span>
<span>Fendix {{.Metadata.Version}}</span>
</div>
<section class="coverage">
<h2>{{.I18n.CoverageTitle}}</h2>
{{if .Metadata.Coverage}}
<p class="coverage-verdict {{if .Metadata.Coverage.ConfiguredComplete}}ok{{else}}gap{{end}}">{{if .Metadata.Coverage.ConfiguredComplete}}{{.I18n.CoverageComplete}}{{else}}{{.I18n.CoverageIncomplete}} {{joinRefs .Metadata.Coverage.Gaps}}{{end}}</p>
{{if .Metadata.Coverage.RequiredGaps}}<p class="coverage-verdict gap">{{.I18n.CoverageRequiredMissing}} {{joinRefs .Metadata.Coverage.RequiredGaps}}</p>{{end}}
<table class="coverage-table">
<thead><tr><th>{{.I18n.CoverageAnalyzer}}</th><th>{{.I18n.CoverageClass}}</th><th>{{.I18n.CoverageReason}}</th><th>{{.I18n.CoverageAttempts}}</th><th>{{.I18n.CoverageDetail}}</th></tr></thead>
<tbody>
{{range .Metadata.ScannerStatus}}<tr class="cov-{{.Class}}"><td>{{.Name}}</td><td>{{classLabel .Class}} <span class="muted">({{.Class}})</span></td><td>{{.Reason}}</td><td>{{if gt .Attempts 1}}{{itoa .Attempts}}{{end}}</td><td>{{.Detail}}</td></tr>
{{end}}</tbody></table>
{{else}}<p class="muted">{{.I18n.CoverageNotRecorded}}</p>{{end}}
</section>
</div>
<script>
function sortFindings(key,btn){
var c=document.getElementById('findings');
var items=[].slice.call(c.querySelectorAll('.finding'));
items.sort(function(a,b){
if(key==='severity')return parseInt(b.dataset.severity)-parseInt(a.dataset.severity);
if(key==='endpoint')return a.dataset.endpoint.localeCompare(b.dataset.endpoint);
if(key==='source')return a.dataset.source.localeCompare(b.dataset.source);
return 0;
});
items.forEach(function(el){c.appendChild(el);});
var btns=document.querySelectorAll('.toolbar button');
btns.forEach(function(b){b.classList.remove('active');});
if(btn)btn.classList.add('active');
}
function toggleAll(open){
var items=document.querySelectorAll('.finding');
items.forEach(function(el){
if(open)el.classList.add('open');
else el.classList.remove('open');
});
}
</script>
</body>
</html>`

// HTMLOptions configures RenderHTMLOpts. Today the only knob is the
// language code (Sprint 10); future options (custom CSS, embedded
// logos) can land here without breaking existing callers.
type HTMLOptions struct {
	// Lang is a BCP-47 language code (e.g. "en", "ar"). Unknown codes
	// fall back to English with i18n.IsSupported returning false; the
	// CLI wrapper is responsible for logging the warning. Empty string
	// is treated as "en".
	Lang string
}

// htmlTemplateData is the struct piped into the HTML template. It
// embeds the existing JSONReport (so all the data shapes the template
// already used continue to work) and adds the Sprint-10 i18n fields.
type htmlTemplateData struct {
	JSONReport
	Lang string
	RTL  bool
	I18n i18n.Strings
}

// RenderHTML writes a self-contained English HTML report to the
// writer. Preserved for backward compatibility with pre-Sprint-10
// callers; new callers should prefer RenderHTMLOpts.
func RenderHTML(w io.Writer, findings []models.Finding, meta ScanMetadata) error {
	return RenderHTMLOpts(w, findings, meta, HTMLOptions{})
}

// RenderHTMLOpts is the Sprint-10 variant of RenderHTML that honours
// HTMLOptions.Lang. The behaviour for opts.Lang=="" or "en" is
// byte-identical to the pre-Sprint-10 output (modulo the new
// <html lang="..."> attribute, which existing CSS doesn't care about).
func RenderHTMLOpts(w io.Writer, findings []models.Finding, meta ScanMetadata, opts HTMLOptions) error {
	lang := opts.Lang
	if lang == "" {
		lang = "en"
	}
	strs := i18n.Get(lang)

	funcMap := template.FuncMap{
		"joinRefs": func(refs []string) string {
			return strings.Join(refs, ", ")
		},
		"derefLine": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
		"formatTime": func(t interface{}) string {
			return fmt.Sprintf("%v", t)
		},
		"severityRank": func(s models.Severity) int {
			return models.SeverityRank(s)
		},
		// `sub` is used by the affected-endpoints "+N more" badge.
		"sub": func(a, b int) int {
			return a - b
		},
		"classLabel":   func(c string) string { return i18n.ClassLabel(strs, c) },
		"verdictLabel": func(d, c string) string { return i18n.VerdictLabel(strs, d, c) },
		"itoa":         func(n int) string { return strconv.Itoa(n) },
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}

	// Strip bidi/zero-width/control characters from untrusted finding
	// fields before they hit the template. html/template auto-escaping
	// handles metachars, but not Trojan-Source bidi reordering or
	// invisible control chars — NeutralizeFindings closes that gap.
	findings = NeutralizeFindings(findings)
	// Same treatment for the coverage table / verdict banner: ScannerStatus
	// and Coverage fields are exactly as operator-controlled under
	// `fendix report --input` as finding fields are.
	meta = NeutralizeCoverageMetadata(meta)
	data := htmlTemplateData{
		JSONReport: JSONReport{
			Metadata:  meta,
			Summary:   CountSeverities(findings),
			Sources:   CountSources(findings),
			Total:     len(findings),
			Decisions: CountStatuses(findings),
			Findings:  findings,
		},
		Lang: lang,
		RTL:  i18n.IsRTL(lang),
		I18n: strs,
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("executing HTML template: %w", err)
	}
	return nil
}
