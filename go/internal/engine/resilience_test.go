package engine

import (
	"strings"
	"testing"

	"github.com/Abdel-RahmanSaied/Fendix/internal/models"
)

// TestResilience_MalformedFindingStream verifies readFindings handles various
// malformed input streams without panicking.
func TestResilience_MalformedFindingStream(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "completely empty",
			input: "",
		},
		{
			name:  "only whitespace",
			input: "   \n\n\t\n   ",
		},
		{
			name:  "binary garbage",
			input: "\x00\x01\x02\x03\xff\xfe\xfd",
		},
		{
			name:  "valid JSON but wrong structure",
			input: `[1, 2, 3]` + "\n",
		},
		{
			name:  "nested objects instead of finding",
			input: `{"a":{"b":{"c":{"d":"deep"}}}}` + "\n",
		},
		{
			name:  "numbers only",
			input: "42\n3.14\n-1\n",
		},
		{
			name:  "string only",
			input: `"just a string"` + "\n",
		},
		{
			name:  "null",
			input: "null\n",
		},
		{
			name:  "true false",
			input: "true\nfalse\n",
		},
		{
			name:  "empty JSON object",
			input: "{}\n",
		},
		{
			name:  "finding with wrong types",
			input: `{"title":123,"severity":true,"source":null,"category":[],"endpoint":{},"evidence":42}` + "\n",
		},
		{
			name:  "extremely long single line",
			input: `{"title":"` + strings.Repeat("x", 100000) + `","severity":"HIGH"}` + "\n",
		},
		{
			name:  "mixed valid and garbage with done",
			input: "garbage\n" + `{"title":"Valid","severity":"HIGH","source":"whitebox","category":"c","endpoint":"e","evidence":"ev","fix":"f","references":[],"confidence":"HIGH"}` + "\n" + "more garbage\n" + `{"done":true,"total":1}` + "\n",
		},
		{
			name:  "done message with error",
			input: `{"done":true,"total":0,"error":"engine crashed"}` + "\n",
		},
		{
			name:  "multiple done messages",
			input: `{"done":true,"total":0}` + "\n" + `{"done":true,"total":0}` + "\n",
		},
		{
			name:  "finding then done then more findings",
			input: `{"title":"A","severity":"HIGH","source":"whitebox","category":"c","endpoint":"e","evidence":"ev","fix":"f","references":[],"confidence":"HIGH"}` + "\n" + `{"done":true,"total":1}` + "\n" + `{"title":"B","severity":"LOW","source":"whitebox","category":"c","endpoint":"e","evidence":"ev","fix":"f","references":[],"confidence":"LOW"}` + "\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sr := readFindings(strings.NewReader(tt.input))
			// Must not panic — all other behavior is acceptable
			_ = sr
		})
	}
}

// TestResilience_CorrelateEdgeCases verifies the correlator handles edge case inputs.
func TestResilience_CorrelateEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		in   int // 0 = nil, 1 = empty, 2+ = count
	}{
		{"nil input", 0},
		{"empty slice", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var findings []models.Finding
			if tt.in == 1 {
				findings = []models.Finding{}
			}
			result := Correlate(findings)
			_ = result // Must not panic
		})
	}
}
