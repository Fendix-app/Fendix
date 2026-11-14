package secrets

import (
	"context"
	"strings"
	"testing"
)

// UTF-32 text (with or without a byte-order mark, either endianness) is text: a
// credential in it is found by the scan and by the search. Before round 5 it was
// "binary" (NUL bytes) to the scan, which skipped it without a word.
func TestScan_UTF32FileIsDecodedNotSkippedAsBinary(t *testing.T) {
	key := "AKIA" + "QZXCVBNMASDFGHJK"
	for name, content := range map[string]string{
		"le-bom.txt": utf32Of("AWS_ACCESS_KEY_ID="+key, false, true),
		"be-bom.txt": utf32Of("AWS_ACCESS_KEY_ID="+key, true, true),
		"le.txt":     utf32Of("AWS_ACCESS_KEY_ID="+key, false, false),
		"be.cfg":     utf32Of("AWS_ACCESS_KEY_ID="+key, true, false),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			writeFile(t, root, name, content)
			fs, err := Scan(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if got := endpointsOf(fs); len(got) == 0 || !strings.Contains(got[0], name) {
				t.Errorf("a UTF-32 credential was not found: %v", got)
			}
		})
	}
}
