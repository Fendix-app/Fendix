package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestDecisionAndPythonHelpDescribeExecutableBehavior(t *testing.T) {
	scan := newScanCmd()
	checks := map[string][]string{
		"fail-on":       {"reaches block", "low"},
		"python-engine": {"--code enables it automatically", "do not bundle"},
		"fast":          {"does not disable the python engine", "--python-engine=false"},
		"offline":       {"known limitation", "--checks auth,injection", "--python-engine=false"},
		"spec":          {"path or http(s) url"},
		"auth-type":     {"apikey-query"},
		"auth-header":   {"query parameter", "api_key"},
	}
	for name, wants := range checks {
		flag := scan.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("scan has no --%s flag", name)
		}
		usage := strings.ToLower(flag.Usage)
		for _, want := range wants {
			if !strings.Contains(usage, want) {
				t.Errorf("--%s help does not contain %q: %q", name, want, flag.Usage)
			}
		}
	}
	if usage := strings.ToLower(scan.Flags().Lookup("fail-on").Usage); strings.Contains(usage, "a corroborated finding") {
		t.Fatalf("--fail-on help still claims every blocking finding must be corroborated: %q", usage)
	}
	if usage := strings.ToLower(scan.Flags().Lookup("deescalate-tests").Usage); strings.Contains(usage, "provider-validated") {
		t.Fatalf("--deescalate-tests calls a provider-shaped match live validation: %q", usage)
	}

	reportHelp := strings.ToLower(newReportCmd().Long)
	for _, format := range []string{"json", "html", "sarif", "pdf"} {
		if !strings.Contains(reportHelp, format) {
			t.Errorf("report help omits supported format %q: %q", format, reportHelp)
		}
	}

	imp := newImportCmd()
	usage := strings.ToLower(imp.Flags().Lookup("enforce-confidence").Usage)
	for _, want := range []string{"low warns", "medium needs an independent signal", "high needs an independent or self-evident signal"} {
		if !strings.Contains(usage, want) {
			t.Errorf("import --enforce-confidence help does not contain %q: %q", want, usage)
		}
	}
}

func TestContractAuditListsEveryExplicitRootCommand(t *testing.T) {
	path := filepath.Join("..", "..", "..", "audits", "engine-contract-reconciliation-2026-10-03.md")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	doc := string(blob)
	for _, command := range newRootCmd().Commands() {
		needle := "`fendix " + command.Name() + "`"
		if !strings.Contains(doc, needle) {
			t.Errorf("contract audit is missing root command %q", command.Name())
		}
	}
	if !strings.Contains(doc, "`fendix completion`") {
		t.Error("contract audit is missing Cobra's generated completion command")
	}
}

func TestContractAuditListsEveryExplicitLeafFlagInItsCommandScope(t *testing.T) {
	path := filepath.Join("..", "..", "..", "audits", "engine-contract-reconciliation-2026-10-03.md")
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	doc := string(blob)
	inventoryStart := strings.Index(doc, "### Full command/flag inventory")
	inventoryEnd := strings.Index(doc, "Three help contracts were corrected")
	if inventoryStart < 0 || inventoryEnd <= inventoryStart {
		t.Fatal("contract audit has no bounded full command/flag inventory")
	}
	inventory := doc[inventoryStart:inventoryEnd]
	scanStart := strings.Index(doc, "`fendix scan` has no positionals")
	scanEnd := strings.Index(doc, "Environment-only command inputs")
	if scanStart < 0 || scanEnd <= scanStart {
		t.Fatal("contract audit has no scoped fendix scan inventory")
	}
	scanScope := doc[scanStart:scanEnd]

	var visit func(*cobra.Command)
	visit = func(cmd *cobra.Command) {
		children := cmd.Commands()
		if len(children) > 0 {
			for _, child := range children {
				visit(child)
			}
			return
		}

		path := cmd.CommandPath()
		var scope string
		if path == "fendix scan" {
			scope = scanScope
		} else {
			needle := "`" + path + "`"
			for _, line := range strings.Split(inventory, "\n") {
				if strings.Contains(line, needle) {
					scope = line
					break
				}
			}
		}
		if scope == "" {
			t.Errorf("contract audit has no inventory scope for %q", path)
			return
		}
		cmd.LocalNonPersistentFlags().VisitAll(func(flag *pflag.Flag) {
			if flag.Name == "help" {
				return
			}
			if !strings.Contains(scope, "--"+flag.Name) {
				t.Errorf("contract audit scope for %q omits --%s", path, flag.Name)
				return
			}
			var descriptor string
			switch flag.Value.Type() {
			case "string":
				descriptor = fmt.Sprintf("--%s string=%q", flag.Name, flag.DefValue)
			default:
				descriptor = fmt.Sprintf("--%s %s=%s", flag.Name, flag.Value.Type(), flag.DefValue)
			}
			if !strings.Contains(scope, descriptor) {
				t.Errorf("contract audit scope for %q does not preserve --%s type/default; want %q", path, flag.Name, descriptor)
			}
		})
	}
	visit(newRootCmd())
}

func TestFlagUsageDoesNotCreateAccidentalPflagMetavariables(t *testing.T) {
	var visit func(*cobra.Command)
	visit = func(cmd *cobra.Command) {
		cmd.LocalNonPersistentFlags().VisitAll(func(flag *pflag.Flag) {
			if strings.Contains(flag.Usage, "`") {
				t.Errorf("%s --%s usage contains a backtick; pflag treats backtick text as the metavar: %q", cmd.CommandPath(), flag.Name, flag.Usage)
			}
		})
		for _, child := range cmd.Commands() {
			visit(child)
		}
	}
	visit(newRootCmd())
}
