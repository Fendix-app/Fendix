package engine

import (
	"reflect"
	"testing"
)

func TestRegistry_OrderIsTheContract(t *testing.T) {
	want := []string{
		"dast", "spec", "active-probes", "secrets", "textscan", "semgrep",
		"govulncheck", "pip", "npm", "python-engine",
		"python-engine/auth", "python-engine/injection", "python-engine/deps", "plugins",
	}
	if !reflect.DeepEqual(Registry, want) {
		t.Fatalf("Registry = %v\nwant %v", Registry, want)
	}
}

func TestIsRegisteredAnalyzer(t *testing.T) {
	for _, n := range Registry {
		if !IsRegisteredAnalyzer(n) {
			t.Errorf("%q must be registered", n)
		}
	}
	for _, n := range []string{"", "Semgrep", "python-taint-engine", "python-engine/secrets"} {
		if IsRegisteredAnalyzer(n) {
			t.Errorf("%q must not be registered", n)
		}
	}
}
