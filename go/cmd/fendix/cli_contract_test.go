package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/policy"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const cliContractStableVersion = "v3.5.1"

type cliContract struct {
	SchemaVersion int                  `json:"schema_version"`
	StableVersion string               `json:"stable_version"`
	Source        string               `json:"source"`
	Commands      []cliContractCommand `json:"commands"`
}

type cliContractCommand struct {
	Path         string            `json:"path"`
	Use          string            `json:"use"`
	Short        string            `json:"short"`
	Availability string            `json:"availability"`
	Runnable     bool              `json:"runnable"`
	Flags        []cliContractFlag `json:"flags"`
}

type cliContractFlag struct {
	Name         string `json:"name"`
	Shorthand    string `json:"shorthand,omitempty"`
	Type         string `json:"type"`
	Default      string `json:"default"`
	NoOptDefault string `json:"no_opt_default,omitempty"`
	Repeatable   bool   `json:"repeatable"`
	Required     bool   `json:"required"`
	Usage        string `json:"usage"`
	Availability string `json:"availability"`
}

type configContract struct {
	SchemaVersion  int                   `json:"schema_version"`
	CurrentVersion int                   `json:"current_version"`
	Source         string                `json:"source"`
	UnknownFields  string                `json:"unknown_fields"`
	FutureVersions string                `json:"future_versions"`
	Precedence     []string              `json:"precedence"`
	Fields         []configContractField `json:"fields"`
}

type configContractField struct {
	Path          string   `json:"path"`
	Type          string   `json:"type"`
	Default       string   `json:"default"`
	Required      bool     `json:"required"`
	AllowedValues []string `json:"allowed_values,omitempty"`
	CLIEquivalent string   `json:"cli_equivalent,omitempty"`
}

type configFieldMetadata struct {
	Type          string
	CLIFlag       string
	Default       string
	Required      bool
	AllowedValues []string
}

var configFieldContract = map[string]configFieldMetadata{
	"version":                 {Type: "integer", Default: "1", Required: true, AllowedValues: []string{"1"}},
	"fail_on":                 {Type: "string", CLIFlag: "fail-on", AllowedValues: []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", ""}},
	"ignore_path":             {Type: "string", CLIFlag: "ignore"},
	"scan.enable_active":      {Type: "boolean", CLIFlag: "enable-active"},
	"scan.workers":            {Type: "integer", CLIFlag: "workers"},
	"scan.timeout":            {Type: "integer", CLIFlag: "timeout"},
	"scan.delay_ms":           {Type: "integer", CLIFlag: "delay"},
	"scan.format":             {Type: "string", CLIFlag: "format", AllowedValues: []string{"json", "html", "sarif", "pdf"}},
	"scan.deescalate_tests":   {Type: "boolean", CLIFlag: "deescalate-tests"},
	"scan.enforce_confidence": {Type: "boolean", CLIFlag: "enforce-confidence"},
	"crawler.crawl_depth":     {Type: "integer", CLIFlag: "crawl-depth"},
	"crawler.max_endpoints":   {Type: "integer", CLIFlag: "max-endpoints"},
	"crawler.wordlist_path":   {Type: "string", CLIFlag: "wordlist"},
	"crawler.respect_robots":  {Type: "boolean", CLIFlag: "respect-robots"},
	"budgets.max_requests":    {Type: "integer", CLIFlag: "max-requests"},
	"budgets.max_duration":    {Type: "duration", CLIFlag: "max-duration"},
	"auth.profile":            {Type: "string", CLIFlag: "profile"},
}

func buildCLIContract() cliContract {
	root := newRootCmd()
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()

	contract := cliContract{
		SchemaVersion: 1,
		StableVersion: cliContractStableVersion,
		Source:        "go/cmd/fendix Cobra registration",
	}
	var visit func(*cobra.Command)
	visit = func(command *cobra.Command) {
		if command != root && !command.Hidden {
			entry := cliContractCommand{
				Path:         command.CommandPath(),
				Use:          command.Use,
				Short:        command.Short,
				Availability: contractAvailability(command.CommandPath()),
				Runnable:     command.Run != nil || command.RunE != nil,
			}
			command.LocalNonPersistentFlags().VisitAll(func(flag *pflag.Flag) {
				if flag.Name == "help" {
					return
				}
				_, required := flag.Annotations[cobra.BashCompOneRequiredFlag]
				entry.Flags = append(entry.Flags, cliContractFlag{
					Name:         flag.Name,
					Shorthand:    flag.Shorthand,
					Type:         flag.Value.Type(),
					Default:      flag.DefValue,
					NoOptDefault: flag.NoOptDefVal,
					Repeatable:   flag.Value.Type() == "stringSlice" || flag.Value.Type() == "stringArray",
					Required:     required,
					Usage:        flag.Usage,
					Availability: contractAvailability(command.CommandPath() + " --" + flag.Name),
				})
			})
			sort.Slice(entry.Flags, func(i, j int) bool { return entry.Flags[i].Name < entry.Flags[j].Name })
			contract.Commands = append(contract.Commands, entry)
		}
		for _, child := range command.Commands() {
			visit(child)
		}
	}
	visit(root)
	sort.Slice(contract.Commands, func(i, j int) bool { return contract.Commands[i].Path < contract.Commands[j].Path })
	return contract
}

func contractAvailability(path string) string {
	if strings.HasPrefix(path, "fendix managed") || strings.Contains(path, "--managed-context") || strings.Contains(path, "--managed-evidence") {
		return "development_only"
	}
	return "stable"
}

func reflectedPolicyPaths(t *testing.T) []string {
	t.Helper()
	var paths []string
	var visit func(reflect.Type, string)
	visit = func(typ reflect.Type, prefix string) {
		if typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			fieldType := field.Type
			if fieldType.Kind() == reflect.Pointer {
				fieldType = fieldType.Elem()
			}
			if fieldType.Kind() == reflect.Struct && fieldType.PkgPath() != "time" {
				visit(fieldType, path)
				continue
			}
			paths = append(paths, path)
		}
	}
	visit(reflect.TypeOf(policy.Policy{}), "")
	sort.Strings(paths)
	return paths
}

func buildConfigContract(t *testing.T) configContract {
	t.Helper()
	paths := reflectedPolicyPaths(t)
	metadataPaths := make([]string, 0, len(configFieldContract))
	for path := range configFieldContract {
		metadataPaths = append(metadataPaths, path)
	}
	sort.Strings(metadataPaths)
	if !reflect.DeepEqual(paths, metadataPaths) {
		t.Fatalf("configuration contract metadata drifted from policy.Policy fields\nreflected: %v\nmetadata:  %v", paths, metadataPaths)
	}

	scanFlags := newScanCmd().Flags()
	contract := configContract{
		SchemaVersion:  1,
		CurrentVersion: policy.SupportedVersion,
		Source:         "go/internal/policy.Policy strict YAML schema",
		UnknownFields:  "rejected",
		FutureVersions: "rejected",
		Precedence:     []string{"defaults", "configuration_file", "explicit_cli_flags"},
	}
	for _, path := range paths {
		metadata := configFieldContract[path]
		defaultValue := metadata.Default
		cliEquivalent := ""
		if metadata.CLIFlag != "" {
			flag := scanFlags.Lookup(metadata.CLIFlag)
			if flag == nil {
				t.Fatalf("configuration field %s maps to missing scan flag --%s", path, metadata.CLIFlag)
			}
			defaultValue = flag.DefValue
			cliEquivalent = "--" + metadata.CLIFlag
		}
		contract.Fields = append(contract.Fields, configContractField{
			Path:          path,
			Type:          metadata.Type,
			Default:       defaultValue,
			Required:      metadata.Required,
			AllowedValues: metadata.AllowedValues,
			CLIEquivalent: cliEquivalent,
		})
	}
	return contract
}

func TestCLIContractArtifactMatchesCobraRegistration(t *testing.T) {
	want := buildCLIContract()
	path := filepath.Join("..", "..", "..", "docs", "cli-contract.json")
	if os.Getenv("UPDATE_CLI_CONTRACT") == "1" {
		blob, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		blob = append(blob, '\n')
		if err := os.WriteFile(path, blob, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated CLI contract: %v (regenerate with UPDATE_CLI_CONTRACT=1 go test ./cmd/fendix -run TestCLIContractArtifactMatchesCobraRegistration)", err)
	}
	var got cliContract
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("decode generated CLI contract: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("docs/cli-contract.json is stale; regenerate with UPDATE_CLI_CONTRACT=1 go test ./cmd/fendix -run TestCLIContractArtifactMatchesCobraRegistration")
	}
}

func TestCLIContractDoesNotCaptureLocalHomeDirectory(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range buildCLIContract().Commands {
		for _, flag := range command.Flags {
			if strings.Contains(flag.Usage, home+string(os.PathSeparator)) {
				t.Fatalf("%s --%s captured the local home directory in public help: %q", command.Path, flag.Name, flag.Usage)
			}
		}
	}
}

func TestConfigurationContractArtifactMatchesStrictPolicySchema(t *testing.T) {
	want := buildConfigContract(t)
	path := filepath.Join("..", "..", "..", "docs", "config-contract.json")
	if os.Getenv("UPDATE_CLI_CONTRACT") == "1" {
		blob, err := json.MarshalIndent(want, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		blob = append(blob, '\n')
		if err := os.WriteFile(path, blob, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated configuration contract: %v (regenerate with UPDATE_CLI_CONTRACT=1 go test ./cmd/fendix -run ContractArtifact)", err)
	}
	var got configContract
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("decode generated configuration contract: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("docs/config-contract.json is stale; regenerate with UPDATE_CLI_CONTRACT=1 go test ./cmd/fendix -run ContractArtifact")
	}
}
