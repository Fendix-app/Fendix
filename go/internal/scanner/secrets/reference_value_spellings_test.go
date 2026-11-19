package secrets

// NEW-E1 follow-up (CL-1b, independent verification VERIFY-SEC C-1).
//
// The anchored reference grammar reported real reference spellings that the old
// line-wide check hid by accident: an ECS valueFrom with a json key, a Helm or
// printf template slot, an IAM wildcard, the literal account "aws", a GCP
// ":access" suffix. Each is a well-formed reference whole, so each stays
// suppressed. The grammar is still anchored at both ends, and a provider-shaped
// token inside a slot or a resource is still reported by its own rule: only the
// generic rules read the reference, and only a value that is entirely one.

import (
	"context"
	"strings"
	"testing"
)

// spellings are references real tools write, each as a whole value.
var spellings = []struct{ name, ref string }{
	// ECS valueFrom: :json-key:version-stage:version-id, the empty fields kept.
	{"ecs-json-key", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:password::"},
	{"ecs-key-and-stage", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:token:AWSCURRENT:"},
	{"ecs-stage-only", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf::AWSPREVIOUS:"},
	{"ecs-version-id-only", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:::0a1b2c3d-4e5f-6789-abcd-ef0123456789"},
	{"ecs-doc-example", "arn:aws:secretsmanager:us-east-1:123456789012:secret:appauthexample-AbCdEf:username1::"},
	// Helm and Jinja slots.
	{"helm-region-account", "arn:aws:secretsmanager:{{ .Values.region }}:{{ .Values.account }}:secret:prod/db-AbCdEf"},
	{"helm-trim-markers", "arn:aws:secretsmanager:{{ $.Values.aws.region }}:{{- .Values.account -}}:secret:{{ .Release.Name }}/db"},
	{"helm-ssm", "arn:aws:ssm:{{ .Values.region }}:{{ .Values.account }}:parameter/{{ .Values.env }}/db/password"},
	{"helm-kms-key", "arn:aws:kms:{{ .Values.region }}:{{ .Values.account }}:key/{{ .Values.keyId }}"},
	{"helm-gcp", "projects/{{ .Values.project }}/secrets/{{ .Values.secret }}/versions/latest"},
	{"helm-pipe", `arn:aws:secretsmanager:{{ .Values.region | quote }}:{{ default .Values.fallback .Values.account }}:secret:prod/db`},
	// printf slots.
	{"printf-s", "arn:aws:secretsmanager:%s:%s:secret:prod/db-AbCdEf"},
	{"printf-named", "arn:aws:secretsmanager:%(region)s:%(account)s:secret:%(name)s"},
	{"printf-ssm", "arn:aws:ssm:%s:%s:parameter/%s/db"},
	{"printf-gcp", "projects/%s/secrets/%s/versions/%s"},
	// $(...) slots.
	{"paren-vars", "arn:aws:secretsmanager:$(REGION):$(ACCOUNT):secret:prod/db-AbCdEf"},
	{"paren-command", "arn:aws:secretsmanager:$(aws configure get region):$(aws sts get-caller-identity --query Account --output text):secret:prod/db-AbCdEf"},
	{"paren-gcp", "projects/$(PROJECT_ID)/secrets/$(SECRET)/versions/latest"},
	// ${...} in the resource, the partition and the GCP names (the region and
	// the account were already allowed).
	{"brace-resource", "arn:aws:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:${Env}/db-AbCdEf"},
	{"brace-partition", "arn:${AWS::Partition}:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:prod/db-AbCdEf"},
	{"brace-gcp", "projects/${PROJECT_ID}/secrets/${SECRET_NAME}/versions/latest"},
	{"brace-gcp-mixed", "projects/my-${ENV}/secrets/db-${ENV}-password"},
	{"terraform", "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:prod/db-AbCdEf"},
	// IAM wildcards.
	{"wild-everything", "arn:aws:secretsmanager:*:*:secret:prod/*"},
	{"wild-region-prefix", "arn:aws:secretsmanager:us-*:123456789012:secret:*"},
	{"wild-ssm", "arn:aws:ssm:*:*:parameter/prod/*"},
	{"wild-kms-key", "arn:aws:kms:*:*:key/*"},
	{"wild-kms-alias", "arn:aws:kms:us-east-1:123456789012:alias/*"},
	// The literal account "aws": a resource AWS owns.
	{"aws-account", "arn:aws:secretsmanager:us-east-1:aws:secret:prod/db-AbCdEf"},
	{"aws-account-kms", "arn:aws:kms:us-east-1:aws:alias/aws/rds"},
	{"kms-alias-aws-rds", "arn:aws:kms:ap-southeast-2:123456789012:alias/aws/rds"},
	// GCP method suffixes.
	{"gcp-access", "projects/my-proj/secrets/db-password/versions/latest:access"},
	{"gcp-access-number", "projects/123456/secrets/db-password/versions/3:access"},
	{"gcp-add-version", "projects/my-proj/secrets/db-password:addVersion"},
	{"gcp-location-access", "projects/my-proj/locations/europe-west1/secrets/db-password/versions/latest:access"},
}

// nonReferences look like the spellings above but are not whole references, so
// a credential-named assignment of one is reported.
var nonReferences = []struct{ name, val string }{
	{"ecs-four-fields", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:password:::Hunter2Hunter2"},
	{"ecs-word-as-version-id", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:password::Hunter2Hunter2"},
	{"ecs-space-in-key", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:pass word::"},
	{"ecs-bang-in-key", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:Hunter2!::"},
	{"ecs-one-field", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:Hunter2Hunter2!"},
	{"wild-no-resource-type", "arn:aws:secretsmanager:*:*:Hunter2Hunter2"},
	{"wild-bad-account", "arn:aws:secretsmanager:*:12345:secret:x"},
	{"slot-with-ampersand", "arn:aws:secretsmanager:{{ Hunter2&x }}:*:secret:x"},
	{"slot-unclosed", "arn:aws:secretsmanager:{{ .Values.region:*:secret:Hunter2"},
	{"printf-no-resource-type", "arn:aws:secretsmanager:%s:%s:Hunter2Hunter2"},
	{"paren-unclosed", "arn:aws:secretsmanager:$(REGION:123456789012:secret:Hunter2"},
	{"kms-short-key-no-slot", "arn:aws:kms:us-east-1:123456789012:key/Hunter2"},
	{"aws-account-bad-resource", "arn:aws:ssm:us-east-1:aws:Hunter2Hunter2"},
	{"aws-account-with-text", "arn:aws:ssm:us-east-1:aws-Hunter2:parameter/x"},
	{"gcp-suffix-then-text", "projects/p/secrets/s/versions/latest:access:Hunter2"},
	{"gcp-unknown-suffix", "projects/p/secrets/s/versions/latest:Hunter2Hunter2"},
	{"gcp-unknown-method", "projects/p/secrets/s/versions/latest:hunter"},
	{"gcp-suffix-glued", "projects/p/secrets/s/versions/latest:accessHunter2"},
	{"gcp-slot-with-ampersand", "projects/{{ Hunter2&x }}/secrets/s"},
	{"gcp-no-secrets-segment", "projects/%s/Hunter2Hunter2"},
	{"gcp-secrets-no-name", "projects/${P}/secrets"},
	{"glued-front", "Xarn:aws:secretsmanager:*:*:secret:x"},
	{"glued-front-gcp", "Xprojects/p/secrets/s:access"},
	{"unknown-partition", "arn:evil:secretsmanager:*:*:secret:x"},
	// Tails the verifier's junk matrix puts after a well-formed reference.
	{"query-string-tail", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf?pw=Hunter2Hunter2"},
	{"ampersand-tail", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf&Hunter2Hunter2"},
	{"percent-tail", "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf%00Hunter2Hunter2"},
	{"wildcard-then-text", "arn:aws:secretsmanager:*:*:secret:prod/* Hunter2Hunter2"},
	{"slot-then-text", "arn:aws:secretsmanager:${AWS::Region}:${AWS::AccountId}:secret:prod/db-AbCdEf Hunter2Hunter2"},
}

func TestNewE1_RealReferenceSpellingsStaySuppressed(t *testing.T) {
	for _, rule := range []struct{ name, line, ctl, file string }{
		{"password", `password = "%s"`, `password = "Tr0ub4dor&3-xylophone"`, "c.py"},
		{"secret_key", `secret_key = "%s"`, `secret_key = "F12Zr47jyXR_` + `XatHjmMLwfKT"`, "c.py"},
		{"api_key", `api_key = "%s"`, `api_key = "k3J9vQ2mX7pL4w` + `N8bT5yR1zA6hD0"`, "c.py"},
		{"env", `DB_PASSWORD=%s`, `DB_PASSWORD=Tr0ub4dor&3-xylophone`, "c.env"},
	} {
		for _, s := range spellings {
			t.Run(rule.name+"/"+s.name, func(t *testing.T) {
				dir := t.TempDir()
				writeFile(t, dir, rule.file, strings.Replace(rule.line, "%s", s.ref, 1)+"\n")
				writeFile(t, dir, "ctl_"+rule.file, rule.ctl+"\n")
				fs, err := Scan(context.Background(), dir)
				if err != nil {
					t.Fatalf("Scan: %v", err)
				}
				if len(e1Findings(t, fs, "ctl_"+rule.file)[1]) == 0 {
					t.Fatalf("control: %q must be reported", rule.ctl)
				}
				if got := e1Findings(t, fs, rule.file); len(got) != 0 {
					t.Errorf("a real reference spelling was reported: %s -> %v", s.ref, got)
				}
			})
		}
	}
}

func TestNewE1_NearReferencesAreStillReported(t *testing.T) {
	for _, n := range nonReferences {
		t.Run(n.name, func(t *testing.T) {
			if isReferenceValue(n.val) {
				t.Errorf("taken for a reference: %q", n.val)
			}
			dir := t.TempDir()
			writeFile(t, dir, "c.py", `password = "`+n.val+`"`+"\n")
			fs, err := Scan(context.Background(), dir)
			if err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if len(e1Findings(t, fs, "c.py")[1]) == 0 {
				t.Errorf("not a whole reference, yet suppressed: %s", n.val)
			}
		})
	}
}

// A provider-shaped token inside a slot, a wildcard position, a resource name
// or a suffix is still reported by the provider's own rule, whatever the
// generic rule does with the value around it.
func TestNewE1_ProviderTokenInsideAReferenceIsStillReported(t *testing.T) {
	tokens := []struct{ id, tok string }{
		{"SEC-GITHUB_TOKEN", "ghp_" + "p7Z3yolXy7wa2HziUY" + "LDxN8oRSUN8x12T7xe"},
		{"SEC-AWS_ACCESS_KEY", "AKIA" + "J4Q7ZP2VNW5XM3RT"},
		{"SEC-STRIPE_LIVE_KEY", "sk_live_" + "51NzQ2rB7mK4" + "vT9xW3pY8cL0d"},
		{"SEC-SLACK_TOKEN", "xoxb-" + "2847561930-5738291046-Q" + "pLmZxCvBnAsDfGhJkLwErTy"},
		{"SEC-GOOGLE_API_KEY", "AIzaSyC4mQ9vK2xT7pL" + "1wN8bZ5yR3zA6hD0eFgH"},
	}
	positions := []string{
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/TOKEN",
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:TOKEN::",
		"arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf::TOKEN:",
		"arn:aws:secretsmanager:{{ TOKEN }}:*:secret:x",
		"arn:aws:secretsmanager:${TOKEN}:aws:secret:x",
		"arn:aws:secretsmanager:$(TOKEN):123456789012:secret:x",
		"arn:aws:secretsmanager:*:*:secret:TOKEN",
		"arn:aws:ssm:*:*:parameter/TOKEN",
		"arn:aws:kms:*:*:alias/TOKEN",
		"projects/TOKEN/secrets/s/versions/latest:access",
		"projects/p/secrets/TOKEN",
		"projects/{{ TOKEN }}/secrets/s",
		"projects/p/secrets/s/versions/TOKEN",
	}
	for _, tk := range tokens {
		for i, pos := range positions {
			value := strings.Replace(pos, "TOKEN", tk.tok, 1)
			for _, line := range []string{`password = "` + value + `"`, `secret_key = '` + value + `'`} {
				dir := t.TempDir()
				writeFile(t, dir, "c.py", line+"\n")
				fs, err := Scan(context.Background(), dir)
				if err != nil {
					t.Fatalf("Scan: %v", err)
				}
				if !e1Has(e1Findings(t, fs, "c.py")[1], tk.id) {
					t.Errorf("position %d: %s inside a reference-shaped value was not reported: %s", i, tk.id, line)
				}
			}
		}
	}
}

// The independent verifier's own cases (VERIFY-SEC cases/e1fp), whole files: every
// real spelling is silent, and the one value that is not a reference (an SSM
// parameter name with spaces) is the one finding.
func TestNewE1_VerifierE1fpCases(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.env", strings.Join([]string{
		`DB_PASSWORD=arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:password::`,
		`API_TOKEN=arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:token:AWSCURRENT:`,
		`DB_PASSWORD=arn:aws:secretsmanager:{{ .Values.region }}:{{ .Values.account }}:secret:prod/db-AbCdEf`,
		`DB_PASSWORD=arn:aws:secretsmanager:*:*:secret:prod/*`,
		`DB_PASSWORD=projects/my-proj/secrets/db-password/versions/latest:access`,
	}, "\n")+"\n")
	writeFile(t, dir, "a.py", strings.Join([]string{
		`password = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf:password::"`,
		`secret_key = "arn:aws:secretsmanager:{{ .Values.region }}:{{ .Values.account }}:secret:prod/db-AbCdEf"`,
		`password = "arn:aws:secretsmanager:${var.region}:${data.aws_caller_identity.current.account_id}:secret:prod/db-AbCdEf"`,
		`secret_key = "arn:aws:secretsmanager:%s:%s:secret:prod/db-AbCdEf" % (r, a)`,
		`password = "arn:aws:ssm:us-east-1:123456789012:parameter/prod/db name with space"`,
		`password = "arn:aws:secretsmanager:us-east-1:aws:secret:prod/db-AbCdEf"`,
		`password = "arn:aws:ssm:eu-west-1:123456789012:parameter/prod/db.password"`,
		`password = "arn:aws:kms:ap-southeast-2:123456789012:alias/aws/rds"`,
		`password = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf-"`,
	}, "\n")+"\n")
	fs, err := Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got := e1Findings(t, fs, "a.env"); len(got) != 0 {
		t.Errorf("a.env: real reference spellings were reported: %v", got)
	}
	got := e1Findings(t, fs, "a.py")
	if len(got) != 1 || !e1Has(got[5], "SEC-HARDCODED_PASSWORD") {
		t.Errorf("a.py: want only line 5 (a parameter name with spaces) reported, got %v", got)
	}
}
