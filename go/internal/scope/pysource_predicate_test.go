package scope_test

// Round 6, WS-E1: the PEP 263 predicate itself (pysource.go), against the same
// generated files the reader tests use, so that the one predicate shared by Go
// and Python (python/tests/test_pep263_vectors.py:test_predicate_*) is pinned
// here too: its verdict and codec on every vector and every codec name,
// takeover immunity on every transparent name, its prefix behaviour, and the
// stream reader the secrets scan and Semgrep target selection use.
//
// The policy is compiled in (scope.codecPolicy) and is the owner's D2-A (OR-85):
// these tests assert the D2-A readings by default. FENDIX_PEP263_POLICY=d2
// asserts the superseded D2 readings, which holds only in a tree whose constant
// was switched back to PolicyD2.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/scope"
)

type wse1PredicateVector struct {
	ID          string            `json:"id"`
	Target      string            `json:"target"`
	Files       map[string]string `json:"files"`
	TargetBytes int               `json:"target_bytes"`
	Expand      *struct {
		Line1CommentBytes int    `json:"line1_comment_bytes"`
		Line1FillToTotal  int    `json:"line1_fill_to_total"`
		Terminator        string `json:"terminator"`
	} `json:"expand"`
	CPython *struct {
		Codec *string `json:"codec"`
	} `json:"cpython"`
	Verdict                  string   `json:"verdict"`
	PredicateVerdicts        []string `json:"predicate_verdicts"`
	PredicateVerdictsUnderD2 []string `json:"predicate_verdicts_under_d2a"`
}

type wse1PredicateVectors struct {
	Vectors []wse1PredicateVector `json:"vectors"`
}

type wse1PredicateName struct {
	Name                     string   `json:"name"`
	Verdict                  string   `json:"verdict"`
	Codec                    *string  `json:"codec"`
	TakeoverImmune           *bool    `json:"takeover_immune"`
	PredicateVerdicts        []string `json:"predicate_verdicts"`
	PredicateVerdictsUnderD2 []string `json:"predicate_verdicts_under_d2a"`
}

func (v wse1PredicateVector) targetBytes(t *testing.T) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(v.Files[v.Target])
	if err != nil {
		t.Fatalf("%s: %v", v.ID, err)
	}
	if e := v.Expand; e != nil {
		n := e.Line1CommentBytes
		if n == 0 {
			n = e.Line1FillToTotal - len(e.Terminator) - len(data)
		}
		line1 := append([]byte("#"), bytes.Repeat([]byte("x"), n-1)...)
		line1 = append(line1, e.Terminator...)
		data = append(line1, data...)
	}
	if len(data) != v.TargetBytes {
		t.Fatalf("%s: %d bytes, the vector file says %d", v.ID, len(data), v.TargetBytes)
	}
	return data
}

func wse1Contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func wse1PredicateAllowed(allowed, underD2A []string) []string {
	if wse1PolicyD2A() && len(underD2A) > 0 {
		return underD2A
	}
	return allowed
}

func wse1CheckPredicate(t *testing.T, what string, got scope.PySource, allowed []string, codec *string) {
	t.Helper()
	if !wse1Contains(allowed, string(got.Verdict)) {
		t.Errorf("%s: predicate says %q, CPython 3.14.5 allows %v", what, got.Verdict, allowed)
		return
	}
	if (got.Verdict == scope.PyForeign || got.Verdict == scope.PyTransparent) && codec != nil && got.Codec != *codec {
		t.Errorf("%s: predicate codec %q, CPython applies %q", what, got.Codec, *codec)
	}
}

func TestPythonSourcePredicateAgreesWithCPythonOnEveryVector(t *testing.T) {
	var doc wse1PredicateVectors
	wse1LoadJSON(t, wse1VectorsFile, &doc)
	checked := 0
	for _, v := range doc.Vectors {
		allowed := wse1PredicateAllowed(v.PredicateVerdicts, v.PredicateVerdictsUnderD2)
		if len(allowed) == 0 {
			continue // a takeover or non-Python vector: the name table carries the spelling's verdict
		}
		t.Run(v.ID, func(t *testing.T) {
			var codec *string
			if v.CPython != nil {
				codec = v.CPython.Codec
			}
			wse1CheckPredicate(t, v.ID, scope.ClassifyPythonSource(v.targetBytes(t), true), allowed, codec)
		})
		checked++
	}
	if checked < 100 {
		t.Fatalf("only %d vectors carry a predicate verdict", checked)
	}
}

func TestPythonSourcePredicateOnEveryCodecName(t *testing.T) {
	var tbl struct {
		Body  string              `json:"body"`
		Names []wse1PredicateName `json:"names"`
	}
	wse1LoadJSON(t, wse1CodecNamesFile, &tbl)
	for _, n := range tbl.Names {
		t.Run(n.Name, func(t *testing.T) {
			got := scope.ClassifyPythonSource([]byte("# coding: "+n.Name+"\n"+tbl.Body), true)
			wse1CheckPredicate(t, "# coding: "+n.Name, got, wse1PredicateAllowed(n.PredicateVerdicts, n.PredicateVerdictsUnderD2), n.Codec)
			// The spelling's takeover immunity is measured per name, never listed.
			if n.Verdict == "transparent" && n.TakeoverImmune != nil && got.Verdict == scope.PyTransparent && got.Immune != *n.TakeoverImmune {
				t.Errorf("# coding: %s: predicate Immune=%v, measured takeover immunity %v", n.Name, got.Immune, *n.TakeoverImmune)
			}
		})
	}
}

// A prefix of a file never gets a verdict the whole file would not: it is
// undeterminable, or it is the complete verdict. Every cut of the first bytes of
// every vector, and a spread of cuts through the rest.
func TestPythonSourcePredicateOnAPrefixNeverGuessesWrong(t *testing.T) {
	var doc wse1PredicateVectors
	wse1LoadJSON(t, wse1VectorsFile, &doc)
	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			data := v.targetBytes(t)
			full := scope.ClassifyPythonSource(data, true)
			cuts := map[int]bool{}
			for i := 0; i <= len(data) && i < 600; i++ {
				cuts[i] = true
			}
			for i := 600; i < len(data); i += len(data)/40 + 1 {
				cuts[i] = true
			}
			for cut := range cuts {
				got := scope.ClassifyPythonSource(data[:cut], false)
				if got.Verdict != scope.PyUndeterminable && got.Verdict != full.Verdict {
					t.Fatalf("%s: the first %d of %d bytes read %q, the whole file reads %q", v.ID, cut, len(data), got.Verdict, full.Verdict)
				}
			}
			if got := scope.ClassifyPythonSource(data, false); got.Verdict != scope.PyUndeterminable && got.Verdict != full.Verdict {
				t.Fatalf("%s: the whole file read as a prefix says %q, as a file %q", v.ID, got.Verdict, full.Verdict)
			}
		})
	}
}

// ClassifyPythonStream reads only as far as it needs, however long line 1 is,
// and hands back what it consumed so a caller can put it back.
func TestClassifyPythonStreamReadsAsFarAsTheVerdictNeeds(t *testing.T) {
	var doc wse1PredicateVectors
	wse1LoadJSON(t, wse1VectorsFile, &doc)
	for _, v := range doc.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			data := v.targetBytes(t)
			want := scope.ClassifyPythonSource(data, true)
			if len(data) > scope.MaxFileBytes+1 {
				// Past the read cap a file does not decide: it is lost, as a file
				// over scope.MaxFileBytes is lost evaluation whatever it holds.
				want = scope.PySource{Verdict: scope.PyUndeterminable}
			}
			got, head, err := scope.ClassifyPythonStream(bytes.NewReader(data), scope.MaxFileBytes+1)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("stream says %+v, the whole file %+v", got, want)
			}
			if !bytes.HasPrefix(data, head) {
				t.Errorf("the bytes handed back are not the start of the file")
			}
			if len(data) <= 8<<10 && len(head) != len(data) && len(head) < 4<<10 {
				t.Errorf("a %d byte file consumed %d bytes", len(data), len(head))
			}
			if file := scope.ClassifyPythonFile(bytes.NewReader(data)); file != want {
				t.Errorf("file reader says %+v, the whole file %+v", file, want)
			}
		})
	}
}

func TestClassifyPythonStreamStopsAtItsLimit(t *testing.T) {
	// A first line that never ends decides nothing within the limit.
	data := append([]byte("#"), bytes.Repeat([]byte("x"), 100<<10)...)
	got, head, err := scope.ClassifyPythonStream(bytes.NewReader(data), 20<<10)
	if err != nil || got.Verdict != scope.PyUndeterminable || len(head) > 20<<10 {
		t.Errorf("limit 20 KiB: %+v, %d bytes, %v; want undeterminable within the limit", got, len(head), err)
	}
}

func TestPythonSourceByNameAndShebang(t *testing.T) {
	for _, tc := range []struct {
		name string
		head string
		want bool
	}{
		{"a.py", "", true}, {"A.PY", "", true}, {"x.pyw", "", true}, {"x.pyi", "", true},
		{"run", "#!/usr/bin/env python3\n", true}, {"run.sh", "#!/usr/bin/python3.12\r\n", true},
		{"run", "#!/bin/sh\n# python is mentioned only here\n", false},
		{"README.md", "# coding: utf-7\n", false}, {"x.sh", "#!/bin/sh\n", false}, {"c.yaml", "", false},
		{"x.pyx", "", false}, {"x.pyc", "", false},
	} {
		if got := scope.IsPythonSource(tc.name, []byte(tc.head)); got != tc.want {
			t.Errorf("IsPythonSource(%q, %q) = %v, want %v", tc.name, strings.TrimSpace(tc.head), got, tc.want)
		}
	}
}

// What this checks: the committed codec table file has its three sections, and a
// name in none of its rows is unknown and lost (no UTF-8 fallback). It does not
// compare the table with the generator's output or with the copy embedded in
// pysource.go: python/tests/test_pep263_vectors.py re-runs the generator on the
// reference interpreter and byte-compares its output, the generator refuses to
// run when the committed table or the Python module's copy is stale, and every
// vector and every codec name above is answered from the embedded copy.
func TestCodecTableFileHasItsSectionsAndAnUnknownNameIsLost(t *testing.T) {
	var onDisk map[string]json.RawMessage
	wse1LoadJSON(t, "testdata/pep263_codec_table.json", &onDisk)
	for _, key := range []string{"aliases", "modules", "fast_path_normal_forms"} {
		if len(onDisk[key]) == 0 {
			t.Errorf("testdata/pep263_codec_table.json has no %q", key)
		}
	}
	// A name in no table row is unknown: no UTF-8 fallback (R6-E1, R6-E6).
	if got := scope.ClassifyPythonSource([]byte("# coding: fendix-no-such-codec\nx = 1\n"), true); got.Verdict != scope.PyUnknown || !got.Lost() {
		t.Errorf("an unknown codec reads %+v, want unknown and lost", got)
	}
}
