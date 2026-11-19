package evidence

import (
	"testing"

	"github.com/Fendix-app/Fendix/go/internal/models"
)

// CL-1 / B-3: a file that starts with "#!" is a script, so its credential is not
// a documentation sample whatever the file is called. NotDocumentation is what
// the scanner that read the first line sets; the index lets it veto InDoc.
func TestNotDocumentationVetoesInDoc(t *testing.T) {
	prose := classEv("INSTALL", nil)
	script := classEv("INSTALL", func(e *Evidence) { e.NotDocumentation = true })
	if !NewProvenanceIndex([]Evidence{prose}).lookup(prose).InDoc {
		t.Fatal("control: a root INSTALL file is documentation")
	}
	if got := NewProvenanceIndex([]Evidence{script}).lookup(script); got.InDoc {
		t.Error("an INSTALL file that starts with #! is a script, not documentation")
	}
	// An explicit producer InDoc does not override the veto.
	both := classEv("docs/entrypoint", func(e *Evidence) { e.NotDocumentation, e.InDoc = true, true })
	if NewProvenanceIndex([]Evidence{both}).lookup(both).InDoc {
		t.Error("InDoc set by a producer outweighed NotDocumentation")
	}
	// The veto survives Restore: evidence that carries it is not made a document again.
	ix := NewProvenanceIndex([]Evidence{script})
	if got := ix.Restore([]Evidence{script})[0]; got.InDoc {
		t.Error("Restore turned a script back into documentation")
	}
	// A script and its documentation neighbour have different occurrence classes,
	// so they never share a finding.
	doc := classEv("docs/guide.md:3", nil)
	scr := classEv("docs/entrypoint:3", func(e *Evidence) { e.NotDocumentation = true })
	ixc := NewProvenanceIndex([]Evidence{doc, scr})
	if ixc.OccurrenceClass(doc.ToFinding()) == ixc.OccurrenceClass(scr.ToFinding()) {
		t.Error("a script and a document share an occurrence class")
	}
	_ = models.SeverityHigh
}
